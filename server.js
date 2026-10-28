import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const root = path.dirname(fileURLToPath(import.meta.url));
try { for (const line of (await fs.readFile(path.join(root, '.env'), 'utf8')).split(/\r?\n/)) { const m = line.match(/^([A-Z_]+)=(.*)$/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2]; } } catch {}
const port = Number(process.env.PORT || 3000);
const supabase = process.env.SUPABASE_URL || 'https://nmiuvczigmuwuiptlnxp.supabase.co';
const key = process.env.SUPABASE_ANON_KEY;
const sessions = new Map();
const send = (res, status, data, headers = {}) => { res.writeHead(status, { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', 'x-content-type-options':'nosniff', ...headers }); res.end(JSON.stringify(data)); };
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=').map(decodeURIComponent)).filter(x => x.length === 2));
const body = async req => { let raw=''; for await (const chunk of req) { raw += chunk; if (raw.length > 8192) throw Error('Request too large'); } return JSON.parse(raw || '{}'); };
const callAuth = async (route, options={}) => { const response = await fetch(`${supabase}/auth/v1/${route}`, { ...options, headers:{ apikey:key, 'content-type':'application/json', ...options.headers } }); const data=await response.json().catch(()=>({})); return {status:response.status, data}; };
const secure = req => req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted;
const sessionCookie = (req, value, maxAge) => `lyriq_session=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure(req)?'; Secure':''}`;
const rate = new Map();
function limited(req) { const ip=req.socket.remoteAddress || 'unknown'; const now=Date.now(); const hits=(rate.get(ip)||[]).filter(t=>now-t<60000); hits.push(now); rate.set(ip,hits); return hits.length>12; }
const server = http.createServer(async (req,res) => {
  try {
    const url=new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      if (!key) return send(res,503,{error:'Configure SUPABASE_ANON_KEY on the server to enable accounts.'});
      const sid=cookies(req).lyriq_session; const session=sessions.get(sid);
      if (req.method==='POST' && ['/api/login','/api/signup'].includes(url.pathname)) {
        if (limited(req)) return send(res,429,{error:'Too many attempts. Try again in a minute.'});
        const input=await body(req); const email=String(input.email||'').trim(); const password=String(input.password||'');
        if (!/^\S+@\S+\.\S+$/.test(email) || password.length<12) return send(res,400,{error:'Enter a valid email and a password of at least 12 characters.'});
        const route=url.pathname==='/api/signup'?'signup':'token?grant_type=password';
        const result=await callAuth(route,{method:'POST',body:JSON.stringify({email,password})});
        if (result.status>=400) return send(res,result.status,{error:result.data.msg || result.data.error_description || result.data.message || 'Authentication failed.'});
        if (!result.data.access_token) return send(res,200,{message:'Check your email to confirm your account.'});
        const id=crypto.randomBytes(32).toString('base64url'); sessions.set(id,{access:result.data.access_token,refresh:result.data.refresh_token,expires:Date.now()+(result.data.expires_in||3600)*1000});
        return send(res,200,{user:result.data.user},{'set-cookie':sessionCookie(req,id,60*60*24*7)});
      }
      if (req.method==='POST' && url.pathname==='/api/logout') { if (sid) sessions.delete(sid); return send(res,200,{ok:true},{'set-cookie':sessionCookie(req,'',0)}); }
      if (!session) return send(res,401,{error:'Sign in to continue.'});
      if (session.expires<Date.now()+60000) { const r=await callAuth('token?grant_type=refresh_token',{method:'POST',body:JSON.stringify({refresh_token:session.refresh})}); if (r.status>=400) { sessions.delete(sid); return send(res,401,{error:'Session expired. Sign in again.'}); } session.access=r.data.access_token; session.refresh=r.data.refresh_token; session.expires=Date.now()+(r.data.expires_in||3600)*1000; }
      if (req.method==='GET' && url.pathname==='/api/me') { const r=await callAuth('user',{headers:{Authorization:`Bearer ${session.access}`}}); return send(res,r.status,r.status<400?{user:r.data}:{error:'Could not load your account.'}); }
      return send(res,404,{error:'Not found.'});
    }
    const file=url.pathname==='/'?'index.html':url.pathname.slice(1);
    if (!['index.html','app.js','style.css','logo.png','icon.png'].includes(file)) { res.writeHead(404); return res.end(); }
    const content=await fs.readFile(path.join(root,'public',file));
    res.writeHead(200,{'content-type': file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':file.endsWith('.png')?'image/png':'text/html; charset=utf-8','content-security-policy':"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'",'x-content-type-options':'nosniff'}); res.end(content);
  } catch (e) { send(res,500,{error:'The request could not be completed.'}); }
});
server.listen(port,()=>console.log(`Lyriq ID running on http://localhost:${port}`));