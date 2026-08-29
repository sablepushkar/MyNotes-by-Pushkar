const express=require("express");
const bcrypt=require("bcryptjs");
const {Pool}=require("pg");
const rateLimit=require("express-rate-limit");
const crypto=require("crypto");
const cookieParser=require("cookie-parser");
const path=require("path");
const fs=require("fs");
const app=express();
const PORT=process.env.PORT||3000;
const SESSION_MS=7*24*60*60*1000;
const USER_TABLE="myprep_users";
const SESSION_TABLE="myprep_sessions";
const FRONTEND_ORIGIN=process.env.FRONTEND_ORIGIN||"https://sablepushkar.github.io";
const ALLOWED_ORIGINS=new Set([FRONTEND_ORIGIN,"https://myprep-3mtm.onrender.com","http://localhost:3000"]);
app.disable("x-powered-by");
app.set("trust proxy",1);
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&ALLOWED_ORIGINS.has(origin)){res.setHeader("Access-Control-Allow-Origin",origin);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Credentials","true");res.setHeader("Access-Control-Allow-Headers","Content-Type");res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,OPTIONS")}if(req.method==="OPTIONS")return res.sendStatus(204);next()});
app.use(express.json({limit:"32kb"}));
app.use(cookieParser());
function databaseUrl(){
  const raw=process.env.DATABASE_URL;
  if(!raw) throw new Error("DATABASE_URL is not configured");
  const u=new URL(raw);
  // Render cannot reach Supabase direct IPv6 endpoints. If DATABASE_URL was
  // accidentally set to the direct db.* endpoint, transparently switch this
  // persistent backend to this project's IPv4 Supavisor session pooler.
  // Render is IPv4-only, so always route this Supabase project through
  // its IPv4 Supavisor session pooler. This also protects against an old
  // direct db.* URL remaining in Render's environment variables.
  if(u.hostname.includes(".supabase.co") && !u.hostname.endsWith("pooler.supabase.com")) {
    u.hostname="aws-0-ap-southeast-1.pooler.supabase.com";
    u.port="5432";
    u.username="postgres.vokqobbqpjuwmyawbrdd";
  }
  u.searchParams.delete("sslmode");
  return u.toString();
}
const caPath=path.join(__dirname,"prod-ca-2021.crt");
const pool=new Pool({connectionString:databaseUrl(),ssl:{ca:fs.readFileSync(caPath,"utf8"),rejectUnauthorized:true},max:5,connectionTimeoutMillis:10000,keepAlive:true});
async function ensureSchema(){await pool.query(`ALTER TABLE ${USER_TABLE} ADD COLUMN IF NOT EXISTS studies JSONB NOT NULL DEFAULT '[]'::jsonb`)}
const usernameRe=/^[A-Za-z0-9]{1,16}$/;
const pinRe=/^\d{4}$/;
const hashToken=t=>crypto.createHash("sha256").update(t).digest("hex");
async function cleanup(){await pool.query(`DELETE FROM ${SESSION_TABLE} WHERE expires_at<=NOW()`)}
async function makeSession(userId){const token=crypto.randomBytes(32).toString("hex"),expires=new Date(Date.now()+SESSION_MS);await pool.query(`INSERT INTO ${SESSION_TABLE}(token_hash,user_id,expires_at) VALUES($1,$2,$3)`,[hashToken(token),userId,expires]);return{token,expires}}
function setCookie(res,token){res.cookie("myprep_session",token,{httpOnly:true,secure:true,sameSite:"none",maxAge:SESSION_MS,path:"/"})}
async function auth(req,res,next){try{await cleanup();const token=req.cookies.myprep_session;if(!token)return res.status(401).json({error:"Login required."});const q=await pool.query(`SELECT u.id,u.username,u.progress,u.studies,s.expires_at FROM ${SESSION_TABLE} s JOIN ${USER_TABLE} u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()`,[hashToken(token)]);if(!q.rows.length){res.clearCookie("myprep_session");return res.status(401).json({error:"Session expired. Please log in again."})}req.user=q.rows[0];next()}catch(e){console.error("AUTH ERROR",e);res.status(500).json({error:"Account service unavailable."})}}
const signupLimiter=rateLimit({windowMs:10*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false});
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Too many PIN attempts. Please try again later."}});
app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true})}catch(e){console.error("HEALTH ERROR",e);res.status(503).json({ok:false})}});
app.post("/api/signup",signupLimiter,async(req,res)=>{const username=String(req.body?.username||"").trim(),pin=String(req.body?.pin||"");if(!usernameRe.test(username))return res.status(400).json({error:"Username must be 1–16 characters and contain letters and numbers only."});if(!pinRe.test(pin))return res.status(400).json({error:"PIN must be exactly 4 digits."});try{const normalized=username.toLowerCase();const exists=await pool.query(`SELECT id FROM ${USER_TABLE} WHERE username=$1`,[normalized]);if(exists.rows.length)return res.status(409).json({error:"That username is already in use."});const pinHash=await bcrypt.hash(pin,12);const q=await pool.query(`INSERT INTO ${USER_TABLE}(username,pin_hash,progress,studies) VALUES($1,$2,$3,$4) RETURNING id,username,progress,studies`,[normalized,pinHash,JSON.stringify([]),JSON.stringify([])]);const s=await makeSession(q.rows[0].id);setCookie(res,s.token);res.status(201).json({username:q.rows[0].username,progress:q.rows[0].progress,studies:q.rows[0].studies||[],expiresAt:s.expires})}catch(e){console.error("SIGNUP ERROR",e);if(e.code==="23505")return res.status(409).json({error:"That username is already in use."});res.status(500).json({error:"Could not create the account."})}});
app.post("/api/login",loginLimiter,async(req,res)=>{const username=String(req.body?.username||"").trim(),pin=String(req.body?.pin||"");if(!usernameRe.test(username)||!pinRe.test(pin))return res.status(401).json({error:"Invalid username or PIN."});try{const q=await pool.query(`SELECT id,username,pin_hash,progress,studies FROM ${USER_TABLE} WHERE username=$1`,[username.toLowerCase()]);const u=q.rows[0];if(!u||!(await bcrypt.compare(pin,u.pin_hash)))return res.status(401).json({error:"Invalid username or PIN."});await pool.query(`DELETE FROM ${SESSION_TABLE} WHERE user_id=$1`,[u.id]);const s=await makeSession(u.id);setCookie(res,s.token);res.json({username:u.username,progress:u.progress||[],studies:u.studies||[],expiresAt:s.expires})}catch(e){console.error("LOGIN ERROR",e);res.status(500).json({error:"Account service unavailable."})}});
app.get("/api/session",auth,(req,res)=>res.json({loggedIn:true,username:req.user.username,progress:req.user.progress||[],studies:req.user.studies||[],expiresAt:req.user.expires_at}));
app.put("/api/progress",auth,async(req,res)=>{if(!Array.isArray(req.body?.progress))return res.status(400).json({error:"Progress must be an array."});const progress=[...new Set(req.body.progress.filter(x=>typeof x==="string").map(x=>x.trim()).filter(Boolean))].slice(0,5000);try{await pool.query(`UPDATE ${USER_TABLE} SET progress=$1 WHERE id=$2`,[JSON.stringify(progress),req.user.id]);res.json({saved:true})}catch(e){console.error("PROGRESS ERROR",e);res.status(500).json({error:"Could not save progress."})}});
app.get("/api/studies",auth,(req,res)=>res.json({studies:Array.isArray(req.user.studies)?req.user.studies:[]}));
app.put("/api/studies",auth,async(req,res)=>{
  if(!Array.isArray(req.body?.studies))return res.status(400).json({error:"Studies must be an array."});
  const raw=req.body.studies;
  if(raw.length>50)return res.status(400).json({error:"Too many study charts."});
  const studies=raw.map(x=>({id:String(x?.id||"").slice(0,80),type:String(x?.type||"").slice(0,30),exam:String(x?.exam||"").slice(0,50),title:String(x?.title||"").slice(0,120),dataKey:String(x?.dataKey||"").slice(0,50),progress:Array.isArray(x?.progress)?[...new Set(x.progress.filter(v=>typeof v==="string").map(v=>v.trim()).filter(Boolean))].slice(0,5000):[],createdAt:String(x?.createdAt||"").slice(0,40)})).filter(x=>x.id&&x.type&&x.exam&&x.dataKey);
  try{await pool.query(`UPDATE ${USER_TABLE} SET studies=$1 WHERE id=$2`,[JSON.stringify(studies),req.user.id]);res.json({saved:true,studies})}catch(e){console.error("STUDIES ERROR",e);res.status(500).json({error:"Could not save study charts."})}
});
app.post("/api/logout",auth,async(req,res)=>{try{const token=req.cookies.myprep_session;if(token)await pool.query(`DELETE FROM ${SESSION_TABLE} WHERE token_hash=$1`,[hashToken(token)]);res.clearCookie("myprep_session");res.json({loggedOut:true})}catch(e){console.error("LOGOUT ERROR",e);res.status(500).json({error:"Could not log out."})}});
app.use(express.static(path.join(__dirname)));
ensureSchema().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log(`MyPrep running on port ${PORT}`))).catch(e=>{console.error("SCHEMA ERROR",e);process.exit(1)});
