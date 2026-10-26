"use strict";

const crypto = require("node:crypto");

function derLen(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, ...parts) {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}

const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const oid = (bytes) => tlv(0x06, Buffer.from(bytes));
const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const utctime = (s) => tlv(0x17, Buffer.from(s, "ascii"));
const bitstr = (b) => tlv(0x03, Buffer.from([0x00]), b);
const octstr = (b) => tlv(0x04, b);
const intBuf = (b) => {
  const pad = b[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), b]) : b;
  return tlv(0x02, pad);
};

// ecdsa-with-SHA256: 1.2.840.10045.4.3.2
const ALG_ECDSA_SHA256 = seq(oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));

function rdnCn(cn) {
  return seq(set(seq(oid([0x55, 0x04, 0x03]), utf8(cn))));
}

function makeCert({ subjectCn, issuerCn, pubSpkiDer, issuerPrivKey, isCa }) {
  const ver = tlv(0xa0, intBuf(Buffer.from([0x02])));
  const serial = intBuf(crypto.randomBytes(8));
  const validity = seq(utctime("250101000000Z"), utctime("350101000000Z"));
  const exts = [];
  if (isCa) {
    exts.push(
      seq(
        oid([0x55, 0x1d, 0x13]),
        tlv(0x01, Buffer.from([0xff])),
        octstr(seq(tlv(0x01, Buffer.from([0xff]))))
      )
    );
    exts.push(
      seq(
        oid([0x55, 0x1d, 0x0f]),
        tlv(0x01, Buffer.from([0xff])),
        octstr(tlv(0x03, Buffer.from([0x02, 0x04])))
      )
    );
  } else {
    exts.push(seq(oid([0x55, 0x1d, 0x13]), octstr(seq())));
    const san = seq(
      tlv(0x87, Buffer.from([127, 0, 0, 1])),
      tlv(0x82, Buffer.from("localhost", "ascii")),
      tlv(0x82, Buffer.from("acme.localhost", "ascii"))
    );
    exts.push(seq(oid([0x55, 0x1d, 0x11]), octstr(san)));
  }
  const tbs = seq(
    ver,
    serial,
    ALG_ECDSA_SHA256,
    rdnCn(issuerCn),
    validity,
    rdnCn(subjectCn),
    pubSpkiDer,
    tlv(0xa3, seq(...exts))
  );
  const sig = crypto.sign("sha256", tbs, issuerPrivKey);
  const certDer = seq(tbs, ALG_ECDSA_SHA256, bitstr(sig));
  const lines = certDer.toString("base64").match(/.{1,64}/g) || [];
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") + "\n-----END CERTIFICATE-----\n";
}

function generateFixtureCerts() {
  const caKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const leafKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const selfKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });

  const testCaCertPem = makeCert({
    subjectCn: "EnvCloak SignIn Test CA",
    issuerCn: "EnvCloak SignIn Test CA",
    pubSpkiDer: caKeys.publicKey.export({ type: "spki", format: "der" }),
    issuerPrivKey: caKeys.privateKey,
    isCa: true,
  });

  const testCaLeafCertPem = makeCert({
    subjectCn: "127.0.0.1",
    issuerCn: "EnvCloak SignIn Test CA",
    pubSpkiDer: leafKeys.publicKey.export({ type: "spki", format: "der" }),
    issuerPrivKey: caKeys.privateKey,
    isCa: false,
  });
  const testCaLeafKeyPem = leafKeys.privateKey.export({ type: "pkcs8", format: "pem" });

  const selfSignedCertPem = makeCert({
    subjectCn: "127.0.0.1",
    issuerCn: "127.0.0.1",
    pubSpkiDer: selfKeys.publicKey.export({ type: "spki", format: "der" }),
    issuerPrivKey: selfKeys.privateKey,
    isCa: false,
  });
  const selfSignedKeyPem = selfKeys.privateKey.export({ type: "pkcs8", format: "pem" });

  return {
    testCaCertPem,
    testCaLeafCertPem,
    testCaLeafKeyPem,
    selfSignedCertPem,
    selfSignedKeyPem,
  };
}

module.exports = {
  generateFixtureCerts,
};
