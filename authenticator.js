import crypto from 'node:crypto';

const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function decodeBase32(value){
  const clean=String(value).toUpperCase().replace(/[\s-]/g,'').replace(/=+$/,'');
  if(clean.length<16||clean.length>256||/[^A-Z2-7]/.test(clean))throw Error('Invalid authenticator secret.');
  let bits=0,buffer=0;const bytes=[];
  for(const char of clean){buffer=(buffer<<5)|alphabet.indexOf(char);bits+=5;if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}}
  if(bytes.length<10)throw Error('Authenticator secret is too short.');
  return Buffer.from(bytes);
}
export function parseAuthenticator(input){
  const raw=String(input||'').trim();
  let secret=raw,issuer='',label='',algorithm='SHA1',digits=6,period=30;
  if(raw.toLowerCase().startsWith('otpauth://')){
    let url;try{url=new URL(raw)}catch{throw Error('Invalid otpauth URI.');}
    if(url.protocol!=='otpauth:'||url.hostname!=='totp')throw Error('Only TOTP accounts are supported.');
    let path;try{path=decodeURIComponent(url.pathname.slice(1))}catch{throw Error('Invalid account label.');}
    if(!path)throw Error('The account name is missing.');
    const split=path.indexOf(':');
    label=(split>=0?path.slice(split+1):path).trim();
    issuer=(url.searchParams.get('issuer')||(split>=0?path.slice(0,split):'')).trim();
    secret=url.searchParams.get('secret')||'';
    algorithm=(url.searchParams.get('algorithm')||'SHA1').toUpperCase();
    digits=Number(url.searchParams.get('digits')||6);
    period=Number(url.searchParams.get('period')||30);
    if(split>=0&&url.searchParams.get('issuer')&&path.slice(0,split)!==issuer)throw Error('Issuer does not match account label.');
  }
  if(!['SHA1','SHA256','SHA512'].includes(algorithm)||![6,8].includes(digits)||![30,60].includes(period))throw Error('Unsupported TOTP settings.');
  const decoded=decodeBase32(secret);
  if(issuer.length>80||label.length>120)throw Error('Account name is too long.');
  return {secret:decoded.toString('base64url'),issuer,label,algorithm,digits,period};
}
export function authenticatorCode(entry,time=Date.now()){
  const counter=Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time/(entry.period*1000))));
  const mac=crypto.createHmac(entry.algorithm.toLowerCase(),Buffer.from(entry.secret,'base64url')).update(counter).digest();
  const offset=mac[mac.length-1]&15;
  const number=(mac.readUInt32BE(offset)&0x7fffffff)%(10**entry.digits);
  return String(number).padStart(entry.digits,'0');
}

