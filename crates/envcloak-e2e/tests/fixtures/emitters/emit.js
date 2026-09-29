// Gate 8's Node serializer for the fixture story (emit.py runs it): for
// each variable name given, the value in this process's environment as
// JSON.stringify writes a string, then NUL, then the SHA-256 of the value
// in hex, then NUL. Nothing else is written, and no error holds a value.
"use strict";
const crypto = require("crypto");
for (const name of process.argv.slice(2)) {
  const value = process.env[name];
  if (value === undefined) {
    process.stderr.write("emit.js: a variable is not set\n");
    process.exit(1);
  }
  const digest = crypto.createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");
  process.stdout.write(Buffer.from(JSON.stringify(value) + "\0" + digest + "\0", "utf8"));
}
