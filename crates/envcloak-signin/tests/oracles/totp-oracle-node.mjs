// Independent composition using Node crypto. stdin is synthetic JSON only;
// stdout contains case labels and booleans, never a seed or a code.
import fs from 'node:fs';
import crypto from 'node:crypto';

function refuse() { throw new Error('invalid_fixture'); }
function decimal(s) {
  if (typeof s !== 'string' || !/^(0|[1-9][0-9]*)$/.test(s)) refuse();
  return BigInt(s);
}
function otp(row) {
  if (!['sha1', 'sha256', 'sha512'].includes(row.algorithm)) refuse();
  if (![6, 8].includes(row.digits)) refuse();
  if (!/^[0-9a-f]+$/.test(row.seed_hex) || row.seed_hex.length % 2 || row.seed_hex.length < 32) refuse();
  const key = Buffer.from(row.seed_hex, 'hex');
  let counter = decimal(row.step);
  if (row.kind === 'time') {
    const now = decimal(row.time), t0 = decimal(row.t0);
    if (!Number.isSafeInteger(row.period) || row.period <= 0 || now < t0) refuse();
    counter = (now - t0) / BigInt(row.period);
  } else if (row.kind !== 'counter') refuse();
  if (counter < 0n || counter > 0xffffffffffffffffn) refuse();
  const moving = Buffer.alloc(8);
  moving.writeBigUInt64BE(counter);
  const digest = crypto.createHmac(row.algorithm, key).update(moving).digest();
  const offset = digest.at(-1) & 15;
  // Explicit byte arithmetic, independent of Python's integer extraction.
  const binary = (digest[offset] & 127) * 16777216 + digest[offset + 1] * 65536
    + digest[offset + 2] * 256 + digest[offset + 3];
  const code = String(binary % 10 ** row.digits).padStart(row.digits, '0');
  key.fill(0); moving.fill(0); digest.fill(0);
  return {code, offset, counter};
}
try {
  const raw = fs.readFileSync(0);
  if (raw.length > 4 * 1024 * 1024) refuse();
  const rows = JSON.parse(raw.toString('utf8'));
  raw.fill(0);
  if (!Array.isArray(rows) || rows.length > 10000) refuse();
  const results = rows.map(row => {
    if (!/^[a-z0-9_-]{1,80}$/.test(row.id)) refuse();
    if (typeof row.expected_code !== 'string' || !/^[0-9]+$/.test(row.expected_code)) refuse();
    const result = otp(row);
    return {id: row.id, matches: result.code === row.expected_code,
      width_matches: result.code.length === row.digits,
      counter_matches: result.counter === decimal(row.step), offset: result.offset};
  });
  process.stdout.write(JSON.stringify({cases: results}));
} catch {
  process.stdout.write(JSON.stringify({error: 'invalid_fixture'}));
  process.exitCode = 2;
}
