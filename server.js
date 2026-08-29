const express = require("express");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
app.disable("x-powered-by");
app.use(express.json({limit:"32kb"}));
app.use(cookieParser());
const db = new Database(process.env.DB_PATH || "myprep.sqlite");
db.pragma("journal_mode = WAL"); db.pragma("foreign_keys = ON");
db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, pin_hash TEXT NOT NULL, progress TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE); CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);`);
const usernameRe=/^[A-Za-z0-9]{1,16}$/; const pinRe=/^\d{4}$/;
function hashToken(t){return crypto.createHash("sha256").update(t).digest("hex")}
function makeSession(userId){const token=crypto.randomBytes(32).toString("hex"),expires=Date.now()+SESSION_MS;db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").run(hashToken(token),userId,expires);return {token,expires}}
function cleanup(){db.prepare("DELETE FROM sessions WHERE expires_at<=?").run(Date.now())}
function auth(req,res,next){cleanup();const token=req.cookies?.myprep_session;if(!token)return res.status(401).json({error:"Login required."});const row=db.prepare("SELECT users.id,users.username,users.progress,sessions.expires_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").get(hashToken(token),Date.now());if(!row){res.clearCookie("myprep_session");return res.status(401).json({error:"Session expired. Please log in again."})}req.user=row;next()}
const signupLimiter=rateLimit({windowMs:10*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false});
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Too many PIN attempts. Please try again later."}});
app.post("/api/signup",signupLimiter,async(req,res)=>{const username=String(req.body?.username||"").trim(),pin=String(req.body?.pin||"");if(!usernameRe.test(username))return res.status(400).json({error:"Username must be 1–16 characters and contain letters and numbers only."});if(!pinRe.test(pin))return res.status(400).json({error:"PIN must be exactly 4 digits."});if(db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE").get(username))return res.status(409).json({error:"That username is already in use."});const pinHash=await bcrypt.hash(pin,12);try{const r=db.prepare("INSERT INTO users(username,pin_hash,progress,created_at) VALUES(?,?,?,?)").run(username,pinHash,"[]",Date.now()),s=makeSession(r.lastInsertRowid);res.cookie("myprep_session",s.token,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",maxAge:SESSION_MS,path:"/"});res.status(201).json({username,progress:[],expiresAt:s.expires})}catch(e){if(String(e.message).includes("UNIQUE"))return res.status(409).json({error:"That username is already in use."});console.error(e);res.status(500).json({error:"Could not create the account."})}});
app.post("/api/login",loginLimiter,async(req,res)=>{const username=String(req.body?.username||"").trim(),pin=String(req.body?.pin||"");if(!usernameRe.test(username)||!pinRe.test(pin))return res.status(401).json({error:"Invalid username or PIN."});const u=db.prepare("SELECT id,username,pin_hash,progress FROM users WHERE username=? COLLATE NOCASE").get(username);if(!u||!(await bcrypt.compare(pin,u.pin_hash)))return res.status(401).json({error:"Invalid username or PIN."});db.prepare("DELETE FROM sessions WHERE user_id=?").run(u.id);const s=makeSession(u.id);res.cookie("myprep_session",s.token,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",maxAge:SESSION_MS,path:"/"});res.json({username:u.username,progress:JSON.parse(u.progress),expiresAt:s.expires})});
app.get("/api/session",auth,(req,res)=>res.json({loggedIn:true,username:req.user.username,progress:JSON.parse(req.user.progress),expiresAt:req.user.expires_at}));
app.put("/api/progress",auth,(req,res)=>{const incoming=req.body?.progress;if(!Array.isArray(incoming))return res.status(400).json({error:"Progress must be an array of task keys."});const progress=[...new Set(incoming.filter(x=>typeof x==="string").map(x=>x.trim()).filter(Boolean).slice(0,5000))];db.prepare("UPDATE users SET progress=? WHERE id=?").run(JSON.stringify(progress),req.user.id);res.json({saved:true})});
app.post("/api/logout",auth,(req,res)=>{const token=req.cookies?.myprep_session;if(token)db.prepare("DELETE FROM sessions WHERE token_hash=?").run(hashToken(token));res.clearCookie("myprep_session");res.json({loggedOut:true})});
app.use(express.static(__dirname));
app.listen(PORT,()=>console.log(`MyPrep account server running on port ${PORT}`));
