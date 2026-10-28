import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { randomId, sha256, seal, unseal, totp } from './security.js';

const root = path.dirname(fileURLToPath(import.meta.url));
try { for (const line of (await fs.readFile(path.join(root, '.env'), 'utf8')).split(/\r?\n/)) { const m = line.match(/^([A-Z_]+)=(.*)$/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2]; } } catch {}
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';
const supabase = process.env.SUPABASE_URL || 'https://nmiuvczigmuwuiptlnxp.supabase.co';
const key = process.env.SUPABASE_SERVER_KEY || process.env.SUPABASE_ANON_KEY;
const encryptionKey = process.env.APP_ENCRYPTION_KEY ? Buffer.from(process.env.APP_ENCRYPTION_KEY, 'base64url') : null;
if (!encryptionKey || encryptionKey.length !== 32) throw Error('APP_ENCRYPTION_KEY must contain 32 random bytes in base64url format.');
const db = new DatabaseSync(path.join(root, 'work', 'lyriq-id.sqlite'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS sessions(id_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,email TEXT NOT NULL,access_enc TEXT NOT NULL,refresh_enc TEXT NOT NULL,expires INTEGER NOT NULL,created_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,user_agent TEXT NOT NULL,revoked_at INTEGER);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id,revoked_at);
CREATE TABLE IF NOT EXISTS service_codes(user_id TEXT NOT NULL,service_id TEXT NOT NULL,secret_enc TEXT NOT NULL,PRIMARY KEY(user_id,service_id));
CREATE TABLE IF NOT EXISTS security_events(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS used_codes(user_id TEXT NOT NULL,service_id TEXT NOT NULL,counter INTEGER NOT NULL,PRIMARY KEY(user_id,service_id,counter));`);
try { db.exec('ALTER TABLE sessions ADD COLUMN mfa_pending INTEGER NOT NULL DEFAULT 0'); } catch {}
const services = [{id:'waterwolf',name:'WaterWolf',letter:'W'},{id:'agentos',name:'AgentOS',letter:'A'},{id:'voxa',name:'VOXA Chat',letter:'V'},{id:'agentpay',name:'Agent Pay',letter:'A'}];
const event = (userId,kind,detail) => db.prepare('INSERT INTO security_events VALUES (?,?,?,?,?)').run(crypto.randomUUID(),userId,kind,detail,Date.now());
function currentSession(req){ const id=cookies(req).lyriq_session; if(!id)return null; const row=db.prepare('SELECT * FROM sessions WHERE id_hash=? AND revoked_at IS NULL').get(sha256(id)); return row && Date.now()-row.created_at<7*86400000 ? row : null; }
const verifiedFactors = user => (user?.factors||[]).filter(f=>f.status==='verified'&&f.factor_type==='totp');
function accountState(row){ const now=Date.now(); const sessionRows=db.prepare('SELECT id_hash,created_at,last_seen,user_agent FROM sessions WHERE user_id=? AND revoked_at IS NULL ORDER BY last_seen DESC').all(row.user_id); const codes=services.map(service=>{let record=db.prepare('SELECT secret_enc FROM service_codes WHERE user_id=? AND service_id=?').get(row.user_id,service.id);if(!record){db.prepare('INSERT OR IGNORE INTO service_codes VALUES (?,?,?)').run(row.user_id,service.id,seal(crypto.randomBytes(32).toString('base64url'),encryptionKey));record=db.prepare('SELECT secret_enc FROM service_codes WHERE user_id=? AND service_id=?').get(row.user_id,service.id)}return {...service,code:totp(Buffer.from(unseal(record.secret_enc,encryptionKey),'base64url'))}});return {user:{id:row.user_id,email:row.email},sessions:sessionRows.map(s=>({...s,id:s.id_hash,current:s.id_hash===row.id_hash})),codes,expires_in:30-Math.floor(now/1000)%30,events:db.prepare('SELECT kind,detail,created_at FROM security_events WHERE user_id=? ORDER BY created_at DESC LIMIT 10').all(row.user_id)} }
const send = (res, status, data, headers = {}) => { res.writeHead(status, { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', 'x-content-type-options':'nosniff', 'x-frame-options':'DENY', 'referrer-policy':'no-referrer', 'permissions-policy':'camera=(), microphone=(), geolocation=()', ...(production?{'strict-transport-security':'max-age=31536000; includeSubDomains'}:{}), ...headers }); res.end(JSON.stringify(data)); };
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=').map(decodeURIComponent)).filter(x => x.length === 2));
const body = async req => { let raw=''; for await (const chunk of req) { raw += chunk; if (raw.length > 8192) throw Error('Request too large'); } return JSON.parse(raw || '{}'); };
const callAuth = async (route, options={}) => { const response = await fetch(`${supabase}/auth/v1/${route}`, { ...options, headers:{ apikey:key, 'content-type':'application/json', ...options.headers } }); const data=await response.json().catch(()=>({})); return {status:response.status, data}; };
const secure = req => req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted;
const sessionCookie = (req, value, maxAge) => `lyriq_session=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure(req)||process.env.NODE_ENV==='production'?'; Secure':''}`;
const rate = new Map();
function limited(req,max=12) { const ip=typeof req==='string'?req:(req.socket.remoteAddress||'unknown'); const now=Date.now(); const hits=(rate.get(ip)||[]).filter(t=>now-t<60000); hits.push(now); rate.set(ip,hits); return hits.length>max; }
const server = http.createServer(async (req,res) => {
  try {
    if(production && !req.socket.encrypted && req.headers['x-forwarded-proto']!=='https') return send(res,400,{error:'HTTPS is required.'});
    const url=new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      if (!key) return send(res,503,{error:'Configure the Supabase server key to enable accounts.'});
      if(['POST','DELETE'].includes(req.method) && req.headers.origin && new URL(req.headers.origin).host!==req.headers.host) return send(res,403,{error:'Invalid request origin.'});
      if(req.method==='POST' && url.pathname==='/api/codes/verify'){
        if(limited(req))return send(res,429,{error:'Too many attempts.'});
        const data=await body(req),service=services.find(s=>s.id===data.client_id),expected=service&&process.env[`LYRIQ_CLIENT_${service.id.toUpperCase()}_SECRET`],provided=String(req.headers.authorization||'').replace(/^Bearer /,'');
        if(limited(`code:${data.client_id}:${data.user_id}`,5))return send(res,429,{error:'Too many attempts.'});
        if(!expected||!provided||expected.length!==provided.length||!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(provided)))return send(res,401,{error:'Unauthorized client.'});
        const record=db.prepare('SELECT secret_enc FROM service_codes WHERE user_id=? AND service_id=?').get(String(data.user_id||''),service.id);
        if(!record||!/^\d{6}$/.test(String(data.code||'')))return send(res,401,{valid:false});
        const secret=Buffer.from(unseal(record.secret_enc,encryptionKey),'base64url'),now=Date.now();let matched=null;
        for(const shift of [-1,0,1]){const counter=Math.floor(now/30000)+shift;if(totp(secret,counter*30000)===String(data.code))matched=counter}
        if(matched===null)return send(res,401,{valid:false});
        try{db.prepare('INSERT INTO used_codes VALUES (?,?,?)').run(String(data.user_id),service.id,matched)}catch{return send(res,401,{valid:false})}
        event(String(data.user_id),'code_used',`${service.name} verification code used`);return send(res,200,{valid:true,user_id:String(data.user_id),client_id:service.id});
      }
      const session=currentSession(req);
      if (req.method==='POST' && ['/api/login','/api/signup'].includes(url.pathname)) {
        if (limited(req)) return send(res,429,{error:'Too many attempts. Try again in a minute.'});
        const input=await body(req); const email=String(input.email||'').trim(); const password=String(input.password||'');
        if (!/^\S+@\S+\.\S+$/.test(email) || password.length<12) return send(res,400,{error:'Enter a valid email and a password of at least 12 characters.'});
        const route=url.pathname==='/api/signup'?'signup':'token?grant_type=password';
        const result=await callAuth(route,{method:'POST',body:JSON.stringify({email,password})});
        if (result.status>=400) return send(res,result.status,{error:result.data.msg || result.data.error_description || result.data.message || 'Authentication failed.'});
        if (!result.data.access_token) return send(res,200,{message:'Check your email to confirm your account.'});
        const info=await callAuth('user',{headers:{Authorization:`Bearer ${result.data.access_token}`}});
        if(info.status>=400)return send(res,502,{error:'Could not verify account factors.'});
        const factor=verifiedFactors(info.data)[0],id=randomId(),now=Date.now();db.prepare('INSERT INTO sessions(id_hash,user_id,email,access_enc,refresh_enc,expires,created_at,last_seen,user_agent,revoked_at,mfa_pending) VALUES (?,?,?,?,?,?,?,?,?,NULL,?)').run(sha256(id),result.data.user.id,result.data.user.email,seal(result.data.access_token,encryptionKey),seal(result.data.refresh_token,encryptionKey),now+(result.data.expires_in||3600)*1000,now,now,String(req.headers['user-agent']||'Unknown device').slice(0,180),factor?1:0);event(result.data.user.id,'sign_in',factor?'Password accepted; second factor required':'Signed in to Lyriq ID');
        return send(res,200,{user:result.data.user,mfa_required:!!factor},{'set-cookie':sessionCookie(req,id,60*60*24*7)});
      }
      if (req.method==='POST' && url.pathname==='/api/logout') { if(session){db.prepare('UPDATE sessions SET revoked_at=? WHERE id_hash=?').run(Date.now(),session.id_hash);event(session.user_id,'sign_out','Signed out of a session')} return send(res,200,{ok:true},{'set-cookie':sessionCookie(req,'',0)}); }
      if (!session) return send(res,401,{error:'Sign in to continue.'});
      if (session.expires<Date.now()+60000) { const r=await callAuth('token?grant_type=refresh_token',{method:'POST',body:JSON.stringify({refresh_token:unseal(session.refresh_enc,encryptionKey)})}); if (r.status>=400) { db.prepare('UPDATE sessions SET revoked_at=? WHERE id_hash=?').run(Date.now(),session.id_hash); return send(res,401,{error:'Session expired. Sign in again.'}); } session.access_enc=seal(r.data.access_token,encryptionKey);session.refresh_enc=seal(r.data.refresh_token,encryptionKey);session.expires=Date.now()+(r.data.expires_in||3600)*1000;db.prepare('UPDATE sessions SET access_enc=?,refresh_enc=?,expires=? WHERE id_hash=?').run(session.access_enc,session.refresh_enc,session.expires,session.id_hash); }
      db.prepare('UPDATE sessions SET last_seen=? WHERE id_hash=?').run(Date.now(),session.id_hash);
      if (req.method==='GET' && url.pathname==='/api/me') return send(res,200,{user:{id:session.user_id,email:session.email},mfa_required:!!session.mfa_pending});
      if (req.method==='GET' && url.pathname==='/api/mfa/factors') {const info=await callAuth('user',{headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`}});if(info.status>=400)return send(res,401,{error:'Could not load security factors.'});return send(res,200,{factors:(info.data.factors||[]).filter(f=>f.factor_type==='totp').map(f=>({id:f.id,status:f.status,friendly_name:f.friendly_name}))});}
      if (req.method==='POST' && url.pathname==='/api/mfa/challenge') { if(limited(req))return send(res,429,{error:'Too many attempts.'});const data=await body(req),factorId=String(data.factor_id||'');const info=await callAuth('user',{headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`}});if(info.status>=400||!(info.data.factors||[]).some(f=>f.id===factorId&&f.factor_type==='totp'))return send(res,403,{error:'Factor not found.'});const r=await callAuth(`factors/${factorId}/challenge`,{method:'POST',headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`},body:'{}'});return send(res,r.status,r.status<400?{challenge_id:r.data.id}:{error:r.data.message||'Could not start challenge.'}); }
      if (req.method==='POST' && url.pathname==='/api/mfa/verify') { if(limited(req))return send(res,429,{error:'Too many attempts.'});const data=await body(req),factorId=String(data.factor_id||''),challengeId=String(data.challenge_id||''),code=String(data.code||'');if(!/^[0-9a-f-]{36}$/i.test(factorId)||!/^[0-9a-f-]{36}$/i.test(challengeId)||!/^\d{6}$/.test(code))return send(res,400,{error:'Invalid verification request.'});const r=await callAuth(`factors/${factorId}/verify`,{method:'POST',headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`},body:JSON.stringify({challenge_id:challengeId,code})});if(r.status>=400)return send(res,r.status,{error:r.data.message||'The code was not accepted.'});db.prepare('UPDATE sessions SET access_enc=?,refresh_enc=?,expires=?,mfa_pending=0 WHERE id_hash=?').run(seal(r.data.access_token,encryptionKey),seal(r.data.refresh_token,encryptionKey),Date.now()+(r.data.expires_in||3600)*1000,session.id_hash);if(!session.mfa_pending)db.prepare('UPDATE sessions SET revoked_at=? WHERE user_id=? AND id_hash<>? AND revoked_at IS NULL').run(Date.now(),session.user_id,session.id_hash);event(session.user_id,'mfa_verified',session.mfa_pending?'Second factor verified':'Second factor enrolled; other sessions revoked');return send(res,200,{ok:true}); }
      if(session.mfa_pending)return send(res,403,{error:'Complete second-factor verification.'});
      if (req.method==='POST' && url.pathname==='/api/mfa/enroll') {const r=await callAuth('factors',{method:'POST',headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`},body:JSON.stringify({factor_type:'totp',friendly_name:'Lyriq ID authenticator'})});return send(res,r.status,r.status<400?{factor_id:r.data.id,secret:r.data.totp?.secret,qr_code:r.data.totp?.qr_code}:{error:r.data.message||'Could not enroll a factor.'});}
      if (req.method==='DELETE' && url.pathname.startsWith('/api/mfa/factors/')) {const factorId=url.pathname.slice('/api/mfa/factors/'.length);if(!/^[0-9a-f-]{36}$/i.test(factorId))return send(res,400,{error:'Invalid factor.'});const info=await callAuth('user',{headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`}});if(info.status>=400||!(info.data.factors||[]).some(f=>f.id===factorId&&f.status==='unverified'))return send(res,403,{error:'Only unverified factors can be cancelled.'});const r=await callAuth(`factors/${factorId}`,{method:'DELETE',headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`}});return send(res,r.status,r.status<400?{ok:true}:{error:r.data.message||'Could not cancel enrollment.'});}
      if (req.method==='GET' && url.pathname==='/api/mfa/recovery') {const r=await callAuth('factors/recovery-codes',{headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`}});return send(res,r.status,r.status<400?{total:r.data.total,remaining:r.data.remaining}:{error:r.data.message||'Recovery codes are not configured.'});}
      if (req.method==='POST' && url.pathname==='/api/mfa/recovery') {const r=await callAuth('factors/recovery-codes',{method:'POST',headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`},body:'{}'});if(r.status<400)event(session.user_id,'recovery_codes','Recovery codes generated');return send(res,r.status,r.status<400?{codes:r.data.codes}:{error:r.data.message||'Could not generate recovery codes.'});}
      if (req.method==='GET' && url.pathname==='/api/state') {const info=await callAuth('user',{headers:{Authorization:`Bearer ${unseal(session.access_enc,encryptionKey)}`}});if(info.status>=400)return send(res,401,{error:'Could not verify your account.'});return send(res,200,{...accountState(session),mfa_enabled:verifiedFactors(info.data).length>0});}
      if (req.method==='POST' && url.pathname==='/api/sessions/revoke') { const data=await body(req),target=String(data.id||'');const found=db.prepare('SELECT id_hash FROM sessions WHERE id_hash=? AND user_id=? AND revoked_at IS NULL').get(target,session.user_id);if(!found)return send(res,404,{error:'Session not found.'});db.prepare('UPDATE sessions SET revoked_at=? WHERE id_hash=?').run(Date.now(),target);event(session.user_id,'session_revoked','A session was revoked');return send(res,200,{ok:true,current:target===session.id_hash},target===session.id_hash?{'set-cookie':sessionCookie(req,'',0)}:{}); }
      if (req.method==='POST' && url.pathname==='/api/sessions/revoke-all') { db.prepare('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').run(Date.now(),session.user_id);event(session.user_id,'sessions_revoked','All sessions were revoked');return send(res,200,{ok:true},{'set-cookie':sessionCookie(req,'',0)}); }
      return send(res,404,{error:'Not found.'});
    }
    const file=url.pathname==='/'?'index.html':url.pathname.slice(1);
    if (!['index.html','app.js','style.css','logo.png','icon.png'].includes(file)) { res.writeHead(404); return res.end(); }
    const content=await fs.readFile(path.join(root,'public',file));
    res.writeHead(200,{'content-type': file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':file.endsWith('.png')?'image/png':'text/html; charset=utf-8','content-security-policy':"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'",'x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'no-referrer','permissions-policy':'camera=(), microphone=(), geolocation=()',...(production?{'strict-transport-security':'max-age=31536000; includeSubDomains'}:{})}); res.end(content);
  } catch (e) { send(res,500,{error:'The request could not be completed.'}); }
});
server.listen(port,production?'0.0.0.0':'127.0.0.1',()=>console.log(`Lyriq ID running on http://localhost:${port}`));