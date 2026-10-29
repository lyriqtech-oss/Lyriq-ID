import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';

const freePort = () => new Promise((resolve, reject) => {
  const socket = net.createServer();
  socket.once('error', reject);
  socket.listen(0, '127.0.0.1', () => {
    const port = socket.address().port;
    socket.close(() => resolve(port));
  });
});

test('account, rotating code, replay protection and session revocation', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'lyriq-test-'));
  const mock = http.createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/auth/v1/token?grant_type=password' && req.method === 'POST') {
      res.end(JSON.stringify({access_token:'test-access',refresh_token:'test-refresh',expires_in:3600,user:{id:'user-1',email:'test@example.com'}}));
    } else if (req.url === '/auth/v1/user') {
      res.end(JSON.stringify({id:'user-1',email:'test@example.com',factors:[]}));
    } else {
      res.statusCode=404;
      res.end('{}');
    }
  });
  const mockPort = await freePort();
  await new Promise(resolve => mock.listen(mockPort,'127.0.0.1',resolve));
  const port = await freePort();
  const child = spawn(process.execPath,['server.js'],{
    cwd:path.resolve('.'),
    env:{...process.env,PORT:String(port),SUPABASE_URL:`http://127.0.0.1:${mockPort}`,SUPABASE_SERVER_KEY:'test-key',APP_ENCRYPTION_KEY:crypto.randomBytes(32).toString('base64url'),LYRIQ_DB_PATH:path.join(directory,'test.sqlite'),LYRIQ_CLIENT_WATERWOLF_SECRET:'test-client-secret',NODE_ENV:'test'},
    stdio:['ignore','pipe','pipe']
  });
  t.after(async()=>{
    if(child.exitCode===null){
      const exited=new Promise(resolve=>child.once('exit',resolve));
      child.kill();
      await exited;
    }
    await new Promise(resolve=>mock.close(resolve));
    await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});
  });
  await new Promise((resolve,reject)=>{
    let output='';
    const timer=setTimeout(()=>reject(new Error(`Server did not start: ${output}`)),5000);
    child.stdout.on('data',chunk=>{output+=chunk; if(output.includes('running on')){clearTimeout(timer);resolve();}});
    child.once('exit',code=>{clearTimeout(timer);reject(new Error(`Server exited: ${code}`));});
  });
  const base=`http://127.0.0.1:${port}`;
  const unauth=await fetch(`${base}/api/state`);
  assert.equal(unauth.status,401);
  const login=await fetch(`${base}/api/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:'test@example.com',password:'correct-horse-battery-staple'})});
  assert.equal(login.status,200);
  const cookie=login.headers.get('set-cookie').split(';')[0];
  assert.match(login.headers.get('set-cookie'),/HttpOnly; SameSite=Strict/);
  const stateResponse=await fetch(`${base}/api/state`,{headers:{cookie}});
  assert.equal(stateResponse.status,200);
  const state=await stateResponse.json();
  assert.equal(state.codes.length,4);
  assert.deepEqual(state.authenticators,[]);
  assert.match(state.codes[0].code,/^\d{6}$/);
  const added=await fetch(`${base}/api/authenticator/entries`,{method:'POST',headers:{cookie,'content-type':'application/json'},body:JSON.stringify({secret:'otpauth://totp/Example:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example'})});
  assert.equal(added.status,201);
  const afterAdd=await (await fetch(`${base}/api/state`,{headers:{cookie}})).json();
  assert.equal(afterAdd.authenticators.length,1);
  assert.equal(afterAdd.authenticators[0].issuer,'Example');
  assert.match(afterAdd.authenticators[0].code,/^\d{6}$/);
  assert.equal('secret' in afterAdd.authenticators[0],false);
  const stored=new DatabaseSync(path.join(directory,'test.sqlite'));
  const encrypted=stored.prepare('SELECT secret_enc FROM authenticator_entries WHERE user_id=?').get('user-1').secret_enc;
  stored.close();
  assert.equal(encrypted.includes('GEZDGNBVGY3TQOJQ'),false);
  const verify=()=>fetch(`${base}/api/codes/verify`,{method:'POST',headers:{authorization:'Bearer test-client-secret','content-type':'application/json'},body:JSON.stringify({client_id:'waterwolf',user_id:'user-1',code:state.codes[0].code})});
  assert.equal((await verify()).status,200);
  assert.equal((await verify()).status,401);
  assert.equal((await fetch(`${base}/api/sessions/revoke-all`,{method:'POST',headers:{cookie}})).status,200);
  assert.equal((await fetch(`${base}/api/state`,{headers:{cookie}})).status,401);
});

test('production rejects a forged HTTPS forwarding header', async t => {
  const directory=await mkdtemp(path.join(os.tmpdir(),'lyriq-proxy-test-'));
  const port=await freePort();
  const child=spawn(process.execPath,['server.js'],{
    cwd:path.resolve('.'),
    env:{...process.env,PORT:String(port),SUPABASE_SERVER_KEY:'test-key',APP_ENCRYPTION_KEY:crypto.randomBytes(32).toString('base64url'),LYRIQ_DB_PATH:path.join(directory,'test.sqlite'),NODE_ENV:'production',TRUST_PROXY:'0'},
    stdio:['ignore','pipe','pipe']
  });
  t.after(async()=>{
    if(child.exitCode===null){const exited=new Promise(resolve=>child.once('exit',resolve));child.kill();await exited;}
    await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});
  });
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('Production server did not start')),5000);
    child.stdout.on('data',chunk=>{if(String(chunk).includes('running on')){clearTimeout(timer);resolve();}});
    child.once('exit',code=>{clearTimeout(timer);reject(new Error(`Production server exited: ${code}`));});
  });
  const response=await fetch(`http://127.0.0.1:${port}/api/me`,{headers:{'x-forwarded-proto':'https'}});
  assert.equal(response.status,400);
  assert.equal((await response.json()).error,'HTTPS is required.');
});

