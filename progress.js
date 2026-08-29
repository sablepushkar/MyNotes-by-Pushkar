/* MyPrep account bridge: keeps the existing MyPrep state object compatible with the account API. */
window.MyPrepAccount = (() => {
  async function request(url, options={}) {
    const res = await fetch(url, {credentials:'same-origin',headers:{'Content-Type':'application/json',...(options.headers||{})},...options});
    const data = await res.json().catch(()=>({}));
    if (!res.ok) throw new Error(data.error || 'Request failed.');
    return data;
  }
  function objectFromIds(ids){const state={};(Array.isArray(ids)?ids:[]).forEach(id=>{if(typeof id==='string'&&id)state[id]=true});return state;}
  function idsFromObject(state){return Object.keys(state||{}).filter(k=>state[k]===true);}
  async function signup(username,pin){return request('/api/signup',{method:'POST',body:JSON.stringify({username,pin})});}
  async function login(username,pin){return request('/api/login',{method:'POST',body:JSON.stringify({username,pin})});}
  async function restoreSession(){try{return await request('/api/session')}catch{return null}}
  async function saveState(state){return request('/api/progress',{method:'PUT',body:JSON.stringify({progress:idsFromObject(state)})});}
  async function logout(){return request('/api/logout',{method:'POST',body:'{}'});}
  return {signup,login,restoreSession,saveState,logout,objectFromIds,idsFromObject};
})();
