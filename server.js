const express=require("express");
const bcrypt=require("bcryptjs");
const {Pool}=require("pg");
const rateLimit=require("express-rate-limit");
const crypto=require("crypto");
const cookieParser=require("cookie-parser");
const path=require("path");
const app=express();
const PORT=process.env.PORT||3000;
const SESSION_MS=7*24*60*60*1000;
const FRONTEND_ORIGIN=process.env.FRONTEND_ORIGIN||"https://sablepushkar.github.io";
const ALLOWED_ORIGINS=new Set([FRONTEND_ORIGIN,"https://myprep-3mtm.onrender.com","http://localhost:3000"]);
app.disable("x-powered-by");
app.set("trust proxy",1);
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&ALLOWED_ORIGINS.has(origin)){res.setHeader("Access-Control-Allow-Origin",origin);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Credentials","true");res.setHeader("Access-Control-Allow-Headers","Content-Type");res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,OPTIONS")}if(req.method==="OPTIONS")return res.sendStatus(204);next()});
app.use(express.json({limit:"32kb"}));
app.use(cookieParser());
if(!process.env.DATABASE_URL)console.warn("DATABASE_URL is not set.");
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:false,max:5});
const usernameRe=/^[A-Za-z0-9]{1,16}$/;
const pinRe=/^\d{4}$/;
const hashToken=t=>crypto.createHash("sha256").update(t).digest("hex");
async function cleanup(){await pool.query("DELETE FROM public.myprep_sessions WHERE expires_at<=NOW()")}
async function makeSession(userId){const token=crypto.randomBytes(32).toString("hex"),expires=new Date(Date.now()+SESSION_MS);await pool.query("INSERT INTO public.myprep_sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)",[hashToken(token),userId,expires]);return{token,expires}}
function setCookie(res,token){res.cookie("myprep_session",token,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:process.env.NODE_ENV==="production"?"none":"lax",maxAge:SESSION_MS,path:"/"})}
async function auth(req,res,next){try{await cleanup();const token=req.cookies.myprep_session;if(!token)return res.status(401).json({error:"Login required."});const q=await pool.query("SELECT u.id,u.username,u.progress,s.expires_at FROM public.myprep_sessions s JOIN public.myprep_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()",[hashToken(token)]);if(!q.rows.length){res.clearCookie("myprep_session");return res.status(401).json({error:"Session expired. Please log in again."})}req.user=q.rows[0];next()}catch(e){console.error(e);res.status(500).json({error:"Account service unavailable."})}}
const signupLimiter=rateLimit({windowMs:10*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false});
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Too many PIN attempts. Please try again later."}});
app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true})}catch(e){res.status(503).json({ok:false})}});
app.post("/api/signup",signupLimiter,async(req,res)=>{const username=String(req.body?.username||"").trim(),pin=String(req.body?.pin||"");if(!usernameRe.test(username))return res.status(400).json({error:"Username must be 1–16 characters and contain letters and numbers only."});if(!pinRe.test(pin))return res.status(400).json({error:"PIN must be exactly 4 digits."});try{const normalized=username.toLowerCase();const exists=await pool.query("SELECT id FROM public.myprep_users WHERE username=$1",[normalized]);if(exists.rows.length)return res.status(409).json({error:"That username is already in use."});const pinHash=await bcrypt.hash(pin,12);const q=await pool.query("INSERT INTO public.myprep_users(username,pin_hash,progress) VALUES($1,$2,$3) RETURNING id,username,progress",[normalized,pinHash,JSON.stringify([])]);const s=await makeSession(q.rows[0].id);setCookie(res,s.token);res.status(201).json({username:q.rows[0].username,progress:q.rows[0].progress,expiresAt:s.expires})}catch(e){if(e.code==="23505")return res.status(409).json({error:"That username is already in use."});console.error(e);res.status(500).json({error:"Could not create the account."})}});
app.post("/api/login",loginLimiter,async(req,res)=>{const username=String(req.body?.username||"").trim(),pin=String(req.body?.pin||"");if(!usernameRe.test(username)||!pinRe.test(pin))return res.status(401).json({error:"Invalid username or PIN."});try{const q=await pool.query("SELECT id,username,pin_hash,progress FROM public.myprep_users WHERE username=$1",[username.toLowerCase()]);const u=q.rows[0];if(!u||!(await bcrypt.compare(pin,u.pin_hash)))return res.status(401).json({error:"Invalid username or PIN."});await pool.query("DELETE FROM public.myprep_sessions WHERE user_id=$1",[u.id]);const s=await makeSession(u.id);setCookie(res,s.token);res.json({username:u.username,progress:u.progress||[],expiresAt:s.expires})}catch(e){console.error(e);res.status(500).json({error:"Account service unavailable."})}});
app.get("/api/session",auth,(req,res)=>res.json({loggedIn:true,username:req.user.username,progress:req.user.progress||[],expiresAt:req.user.expires_at}));
app.put("/api/progress",auth,async(req,res)=>{if(!Array.isArray(req.body?.progress))return res.status(400).json({error:"Progress must be an array."});const progress=[...new Set(req.body.progress.filter(x=>typeof x==="string").map(x=>x.trim()).filter(Boolean).slice(0,5000))];try{await pool.query("UPDATE public.myprep_users SET progress=$1 WHERE id=$2",[JSON.stringify(progress),req.user.id]);res.json({saved:true})}catch(e){console.error(e);res.status(500).json({error:"Could not save progress."})}});
app.post("/api/logout",auth,async(req,res)=>{try{const token=req.cookies.myprep_session;if(token)await pool.query("DELETE FROM public.myprep_sessions WHERE token_hash=$1",[hashToken(token)]);res.clearCookie("myprep_session");res.json({loggedOut:true})}catch(e){console.error(e);res.status(500).json({error:"Could not log out."})}});
app.use(express.static(path.join(__dirname)));
app.listen(PORT,"0.0.0.0",()=>console.log(`MyPrep running on port ${PORT}`));