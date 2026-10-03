// An independent reading of host names, for tests/encoding.rs: Node's
// WHATWG URL parser, which follows the browser's URL standard, serializes
// each candidate host. Adapted from the origin-parsing oracle's helper:
// pure parsing, no network, no base URL. Generated names enter on standard
// input as a JSON array of strings; for each, the hostname the parser
// serializes for `https://<name>/` leaves, or null where it refuses the
// URL. Shares no code with the crate.
import fs from 'node:fs';

const bytes = fs.readFileSync(0);
if (bytes.length > 1024 * 1024) {
  console.log(JSON.stringify({ error: 'input over 1 MiB' }));
  process.exit(1);
}
const names = JSON.parse(bytes.toString('utf8'));
const hostnames = names.map((name) => {
  try {
    return new URL('https://' + name + '/').hostname;
  } catch {
    return null;
  }
});
console.log(JSON.stringify({ node: process.version, hostnames }));
