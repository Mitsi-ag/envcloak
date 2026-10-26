"use strict";

const crypto = require("node:crypto");

function normalizeAlgorithm(alg) {
  const up = String(alg || "SHA1").toUpperCase().replace(/-/g, "");
  if (up === "SHA1") return "sha1";
  if (up === "SHA256") return "sha256";
  if (up === "SHA512") return "sha512";
  throw new Error(`unsupported_totp_algorithm:${alg}`);
}

function generateTotp({
  secretHex,
  timestampSecs,
  periodSecs = 30,
  digits = 8,
  algorithm = "SHA1",
}) {
  if (digits !== 6 && digits !== 8) {
    throw new Error(`unsupported_totp_digits:${digits}`);
  }
  const nodeAlg = normalizeAlgorithm(algorithm);
  const key = Buffer.from(String(secretHex), "hex");
  const step = BigInt(Math.floor(Number(timestampSecs) / Number(periodSecs)));
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(step, 0);

  const digest = crypto.createHmac(nodeAlg, key).update(counterBuf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  const mod = digits === 8 ? 100000000 : 1000000;
  const code = String(binary % mod).padStart(digits, "0");
  return {
    code,
    step: Number(step),
    digits,
    algorithm: nodeAlg.toUpperCase(),
  };
}

function verifyTotp({
  secretHex,
  timestampSecs,
  periodSecs = 30,
  digits = 8,
  algorithm = "SHA1",
  code,
}) {
  const candidate = String(code || "").trim();
  if (!/^\d+$/.test(candidate) || (candidate.length !== 6 && candidate.length !== 8)) {
    return { valid: false, expected: null, step: null };
  }
  const effectiveDigits = digits || candidate.length;
  const computed = generateTotp({
    secretHex,
    timestampSecs,
    periodSecs,
    digits: effectiveDigits,
    algorithm,
  });
  const a = Buffer.from(candidate, "ascii");
  const b = Buffer.from(computed.code, "ascii");
  const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
  return {
    valid,
    expected: computed.code,
    step: computed.step,
    digits: computed.digits,
    algorithm: computed.algorithm,
  };
}

module.exports = {
  generateTotp,
  verifyTotp,
};
