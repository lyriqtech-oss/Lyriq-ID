import crypto from 'node:crypto';

export const randomId = () => crypto.randomBytes(32).toString('base64url');
export const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
export function seal(value, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
}
export function unseal(value, key) {
  const data = Buffer.from(value, 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8');
}
export function totp(secret, time = Date.now(), digits = 6) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 30000)));
  const mac = crypto.createHmac('sha256', secret).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  const value = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(value).padStart(digits, '0');
}
export function verifyTotp(secret, code, time = Date.now()) {
  if (!/^\d{6}$/.test(String(code))) return false;
  return [-30000, 0, 30000].some(delta => crypto.timingSafeEqual(Buffer.from(totp(secret, time + delta)), Buffer.from(String(code))));
}