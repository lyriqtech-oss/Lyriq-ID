import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseAuthenticator,authenticatorCode} from '../authenticator.js';

test('imports standard otpauth URI and produces RFC 6238 SHA-1 code',()=>{
  const entry=parseAuthenticator('otpauth://totp/Example:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=8&period=30');
  assert.equal(entry.issuer,'Example');
  assert.equal(entry.label,'alice@example.com');
  assert.equal(authenticatorCode(entry,59000),'94287082');
});

test('rejects malformed authenticator input',()=>{
  assert.throws(()=>parseAuthenticator('otpauth://hotp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'));
  assert.throws(()=>parseAuthenticator('otpauth://totp/Example?secret=ABCDEF'));
  assert.throws(()=>parseAuthenticator('otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=1'));
});

