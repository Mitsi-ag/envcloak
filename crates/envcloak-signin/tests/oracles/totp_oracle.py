"""Cycle206 independent oracle, adapted for reproducible test fixtures.

No product imports. RFC hashes and Node composition stay independent.
Synthetic seeds/codes are byte arrays in the fixture; diagnostics are counts.
"""
from pathlib import Path
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REF = HERE / "totp-rfc6238-reference.json"

class Synthetic:
    def __init__(self):
        self.counter = 0
    def token_bytes(self, length):
        self.counter += 1
        return hashlib.shake_256(f"envcloak-totp-fixture-{self.counter}".encode()).digest(length)

secrets = Synthetic()
ALGS = ('sha1', 'sha256', 'sha512')
MAX_COUNTER = 2**64 - 1

def fail():
    raise ValueError('invalid_parameter')

def valid_counter(n):
    if type(n) is not int or not 0 <= n <= MAX_COUNTER:
        fail()

def moving_factor(now, period=30, t0=0):
    if any(type(v) is not int for v in (now, period, t0)) or period <= 0 or t0 < 0 or now < t0:
        fail()
    n = (now - t0) // period
    valid_counter(n)
    return n

def calculate(seed, algorithm, digits, counter, mutant=None):
    if not isinstance(seed, bytes) or len(seed) < 16 or algorithm not in ALGS or type(digits) is not int or digits not in (6, 8):
        fail()
    valid_counter(counter)
    if mutant == 'counter-u32': counter &= 0xffffffff
    if mutant == 'counter-float': counter = min(MAX_COUNTER, int(float(counter)))
    if mutant == 'always-sha1': algorithm = 'sha1'
    if mutant == 'seed-first20': seed = seed[:20]
    if mutant == 'seed-strip-zero': seed = seed.rstrip(b'\0')
    message = counter.to_bytes(8, 'little' if mutant == 'counter-little-endian' else 'big')
    digest = hmac.digest(message, seed, algorithm) if mutant == 'reverse-hmac-inputs' else hmac.digest(seed, message, algorithm)
    offset = (digest[19] if mutant == 'offset-byte19' else digest[-1]) & 15
    if mutant == 'fixed-offset0': offset = 0
    binary = int.from_bytes(digest[offset:offset+4], 'big')
    if mutant != 'unmasked-sign': binary &= 0x7fffffff
    width = 6 if mutant == 'always-six-digits' else digits
    code = str(binary % 10**width)
    if mutant != 'no-zero-pad': code = code.zfill(width)
    return code, offset

def cases():
    reference = json.loads(REF.read_text())
    assert len(reference['rows']) == 18
    rows, rfc_checks = [], 0
    def add(name, seed, alg, digits, counter, kind='counter', **extra):
        code, offset = calculate(seed, alg, digits, counter)
        row = dict(id=name, kind=kind, seed_hex=seed.hex(), algorithm=alg, digits=digits,
                   step=str(counter), expected_code=code, offset=offset, **extra)
        rows.append(row)
        return row
    # Verified erratum2866 changes the Appendix B prose, not the table.
    # Generate the public ASCII seed recipe without ever displaying it.
    digit_cycle = bytes(range(49, 58)) + bytes([48])
    for r in reference['rows']:
        seed = (digit_cycle * 7)[:r['seed_length']]
        for digits in (6, 8):
            row = add(r['id']+'-d'+str(digits), seed, r['algorithm'], digits, int(r['step']),
                      'time', time=r['time'], t0=r['t0'], period=r['period'])
            assert hashlib.sha256(row['expected_code'].encode()).hexdigest() == r['expected'+str(digits)+'_sha256'], 'RFC mismatch'
            rfc_checks += 1
    boundary_steps = [0,1,2,2**31-1,2**31,2**32-1,2**32,2**53-1,2**53+1,2**63-1,2**63,MAX_COUNTER]
    for alg in ALGS:
        for digits in (6, 8):
            for length in (16,20,32,63,64,65,127,128,129,256):
                seed = b'\0' + secrets.token_bytes(length-2) + b'\0'
                for j, counter in enumerate(boundary_steps):
                    add(f'random-{alg}-d{digits}-k{length}-s{j}', seed, alg, digits, counter)
            for period in (15,30,45,60):
                for t0 in (0,17):
                    seed = secrets.token_bytes(32)
                    for i, delta in enumerate((-1,0,1,period-3,period-2,period-1)):
                        now = t0 + 10*period + delta
                        add(f'time-{alg}-d{digits}-p{period}-t{t0}-b{i}',seed,alg,digits,
                            moving_factor(now,period,t0),'time',time=str(now),t0=str(t0),period=period)
            # Explicit zero-prefix and all dynamic-offset witnesses. No value
            # is returned in diagnostics; each search has a fixed work bound.
            seed = secrets.token_bytes(32); seen = set(); zero = False
            for counter in range(4096):
                code, offset = calculate(seed,alg,digits,counter)
                wanted = offset not in seen or (not zero and code.startswith('0'))
                if wanted:
                    add(f'witness-{alg}-d{digits}-s{counter}',seed,alg,digits,counter)
                    seen.add(offset); zero |= code.startswith('0')
                if len(seen)==16 and zero: break
            assert len(seen)==16 and zero, 'bounded witness generation failed'
    assert len({r['id'] for r in rows})==len(rows)
    return rows, rfc_checks

def mutation_checks(rows):
    primitive = ['counter-little-endian','counter-u32','counter-float','always-sha1',
                 'offset-byte19','fixed-offset0','unmasked-sign','no-zero-pad',
                 'always-six-digits','seed-first20','seed-strip-zero','reverse-hmac-inputs']
    results = []
    for name in primitive:
        differences = sum(calculate(bytes.fromhex(r['seed_hex']),r['algorithm'],r['digits'],int(r['step']),name)[0] != r['expected_code'] for r in rows)
        results.append({'mutant':name,'differing_cases':differences,'detected':differences>0})
    for name in ('time-ceil','ignore-t0','period-always30','time-round-nearest','period-milliseconds'):
        differences = 0
        for r in rows:
            if r['kind']!='time': continue
            now,t0,p = int(r['time']),int(r['t0']),r['period']; delta=now-t0
            n = {'time-ceil':(delta+p-1)//p,'ignore-t0':now//p,'period-always30':delta//30,
                 'time-round-nearest':(delta+p//2)//p,'period-milliseconds':delta//(p*1000)}[name]
            differences += calculate(bytes.fromhex(r['seed_hex']),r['algorithm'],r['digits'],n)[0] != r['expected_code']
        results.append({'mutant':name,'differing_cases':differences,'detected':differences>0})
    assert all(r['detected'] for r in results), 'mutation control missed'
    return results

def invalid_controls():
    seed = secrets.token_bytes(32)
    fns = [lambda v=v:calculate(seed,'sha1',6,v) for v in (-1,2**64,True,1.5,'1')]
    fns += [lambda v=v:calculate(seed,'sha1',v,1) for v in (5,7,9,6.0)]
    fns += [lambda:calculate(seed,'sha384',6,1),lambda:calculate(b'','sha1',6,1)]
    fns += [lambda args=args:moving_factor(*args) for args in ((-1,30,0),(10,0,0),(10,-1,0),(10,30,11),(10,30,-1),(1.5,30,0),(10,30.0,0),(True,30,0),(2**70,1,0))]
    for fn in fns:
        try: fn()
        except ValueError as e: assert str(e)=='invalid_parameter'
        else: raise AssertionError('invalid control accepted')
    return len(fns)


def main():
    rows, refs = cases()
    controls = mutation_checks(rows)
    invalid = invalid_controls()
    payload = json.dumps(rows).encode()
    # Never inherit HOME, credentials, runtime options or agent markers.
    with tempfile.TemporaryDirectory(prefix="otp-", dir=os.environ["TMPDIR"]) as home:
        env = {"PATH":os.environ["PATH"], "HOME":home, "TMPDIR":home, "LC_ALL":"C"}
        result = subprocess.run(["node", str(HERE / "totp-oracle-node.mjs")], input=payload, capture_output=True, env=env, check=False)
        assert result.returncode == 0 and not result.stderr, "Node oracle failed"
        observed = json.loads(result.stdout)["cases"]
        assert len(observed) == len(rows)
        assert all(x["matches"] and x["width_matches"] and x["counter_matches"] and x["offset"] == r["offset"] for x,r in zip(observed,rows)), "Node mismatch"
        bad = dict(rows[0]); bad["expected_code"] = "0" * bad["digits"]
        wrong = subprocess.run(["node", str(HERE / "totp-oracle-node.mjs")], input=json.dumps([bad]).encode(), capture_output=True, env=env, check=False)
        assert wrong.returncode == 0 and not json.loads(wrong.stdout)["cases"][0]["matches"], "Node positive control failed"
    clean = []
    for row in rows:
        row = dict(row)
        seed = bytes.fromhex(row.pop("seed_hex"))
        row["seed"] = list(seed)
        row["base32"] = list(base64.b32encode(seed).rstrip(b"="))
        row["expected_code"] = list(row["expected_code"].encode())
        clean.append(row)
    data = ("[\n" + ",\n".join(json.dumps(row, separators=(",", ":")) for row in clean) + "\n]\n").encode()
    target = HERE / "totp-cases.json"
    if sys.argv[1:] == ["--write"]:
        target.write_bytes(data)
    else:
        assert not sys.argv[1:], "invalid argument"
        assert target.read_bytes() == data, "fixture drift"
    print(f"TOTP oracle: {refs} RFC checks; {len(rows)} Python/Node comparisons; {len(controls)} mutant controls; {invalid} invalid controls; wrong-code positive control passed")

if __name__ == "__main__":
    main()
