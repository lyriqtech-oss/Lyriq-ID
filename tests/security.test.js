import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { randomId, sha256, seal, unseal, totp, verifyTotp } from '../security.js';

test('session identifiers are random and hashable', () => {
  const a=randomId(),b=randomId();
  assert.notEqual(a,b);assert.equal(sha256(a).length,64);
});
test('encrypted secrets round trip and reject a different key', () => {
  const key=crypto.randomBytes(32),other=crypto.randomBytes(32),encrypted=seal('private-value',key);
  assert.equal(unseal(encrypted,key),'private-value');
  assert.throws(()=>unseal(encrypted,other));
});
test('codes rotate every 30 seconds and reject invalid input', () => {
  const secret=crypto.randomBytes(32),time=60000;
  const code=totp(secret,time);
  assert.match(code,/^\d{6}$/);
  assert.equal(verifyTotp(secret,code,time),true);
  assert.equal(verifyTotp(secret,'not a code',time),false);
  assert.notEqual(totp(secret,time),totp(secret,time+30000));
});
test('TOTP matches the RFC 6238 SHA-256 test vector', () => {
  const secret=Buffer.from('12345678901234567890123456789012');
  assert.equal(totp(secret,59000,8),'46119246');
});