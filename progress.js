/* MyPrep account bridge: persistent account progress with the deployed backend. */
window.MyPrepAccount=(()=>{
 const API_BASE=(location.hostname.endsWith("github.io")||location.protocol==="file:")?"https://myprep-3mtm.onrender.com":"";
 function objectFromIds(ids){const o={};(Array.isArray(ids)?ids:[]).forEach(id=>o[id]=true);return o}
 function idsFromObject(state){return Object.keys(state||{}).filter(k=>state[k])}
 async function request(path,options={}){const r=await fetch(API_BASE+path,{credentials:"include",headers:{"Content-Type":"application/json",...(options.headers||{})},...options});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Request failed.");return d}
 async function signup(username,pin){return request("/api/signup",{method:"POST",body:JSON.stringify({username:String(username).trim(),pin:String(pin)})})}
 async function login(username,pin){return request("/api/login",{method:"POST",body:JSON.stringify({username:String(username).trim(),pin:String(pin)})})}
 async function restoreSession(){try{return await request("/api/session")}catch{return null}}
 async function getStudies(){const d=await request("/api/studies");return Array.isArray(d.studies)?d.studies:[]}
 async function saveStudies(studies){return request("/api/studies",{method:"PUT",body:JSON.stringify({studies:Array.isArray(studies)?studies:[]})})}
 async function saveState(state){return request("/api/progress",{method:"PUT",body:JSON.stringify({progress:idsFromObject(state)})})}
 async function logout(){return request("/api/logout",{method:"POST",body:"{}"})}
 return{signup,login,restoreSession,saveState,getStudies,saveStudies,logout,objectFromIds,idsFromObject}
})();