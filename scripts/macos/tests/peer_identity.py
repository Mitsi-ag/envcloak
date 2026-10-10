"""Create native signing fixtures in a caller-owned directory, with no real credentials."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
EXCEPTIONS = ["allow-jit", "allow-unsigned-executable-memory", "allow-dyld-environment-variables",
              "disable-library-validation", "disable-executable-page-protection", "debugger"]


def prepare(root):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = {"HOME": str(root), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": str(root)}
    if "DEVELOPER_DIR" in os.environ:
        env["DEVELOPER_DIR"] = os.environ["DEVELOPER_DIR"]

    def run(*args):
        r = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if r.returncode:
            raise RuntimeError(args[0] + " exit " + str(r.returncode) + ": " + r.stderr.decode(errors="replace"))
        return r.stdout

    run("/usr/bin/clang", "-fobjc-arc", "-Wno-deprecated-declarations", "-framework", "Foundation", "-framework", "Security", str(ROOT / "crates/envcloak-sys/tests/fixtures/sign_peer.m"), "-o", str(root / "sign_peer"))
    identities = json.loads((root / "identities.json").read_text()) if (root / "identities.json").exists() else []
    for name in ([] if identities else ["trusted", "foreign"]):
        directory = root / name
        directory.mkdir(mode=0o700)
        password = os.urandom(24).hex()
        keychain = directory / "fixture.keychain-db"
        config = directory / "certificate.cnf"
        config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
                          f"[dn]\nCN=EnvCloak Fixture {name} {os.urandom(8).hex()}\n"
                          "[ext]\nbasicConstraints=critical,CA:true\n"
                          "keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\n")
        run("/usr/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-config", str(config), "-keyout", str(directory / "key.pem"),
            "-out", str(directory / "cert.pem"))
        run("/usr/bin/openssl", "pkcs12", "-export", "-inkey", str(directory / "key.pem"),
            "-in", str(directory / "cert.pem"), "-out", str(directory / "identity.p12"),
            "-passout", "pass:" + password)
        run("/usr/bin/security", "create-keychain", "-p", password, str(keychain))
        run("/usr/bin/security", "unlock-keychain", "-p", password, str(keychain))
        run("/usr/bin/security", "set-keychain-settings", "-t", "21600", str(keychain))
        run("/usr/bin/security", "import", str(directory / "identity.p12"), "-k", str(keychain),
            "-P", password, "-A")
        der = run("/usr/bin/openssl", "x509", "-in", str(directory / "cert.pem"), "-outform", "DER")
        (directory / "cert.der").write_bytes(der)
        identities.append({"keychain": str(keychain), "certificate": str(directory / "cert.der"), "sha1": hashlib.sha1(der).hexdigest()})
    (root / "identities.json").write_text(json.dumps(identities))
    base = root / "base"
    run("/usr/bin/clang", "-Wall", "-Wextra", "-Werror", str(ROOT / "scripts/macos/tests/peer_fixture.c"),
        "-o", str(base))
    for name, identity, runtime, entitlement in [
        ("genuine", 0, True, None), ("foreign", 1, True, None),
        ("adhoc", None, True, None), ("unsigned", None, False, None),
        ("no-runtime", 0, False, None),
        ("debuggable", 0, True, "com.apple.security.get-task-allow"),
        *[(exception, 0, True, "com.apple.security.cs." + exception) for exception in EXCEPTIONS],
        ("debuggable-false", 0, True, "com.apple.security.get-task-allow"),
        *[(exception + "-false", 0, True, "com.apple.security.cs." + exception) for exception in EXCEPTIONS],
    ]:
        import shutil
        file = root / (name + "-peer")
        file.unlink(missing_ok=True)
        shutil.copyfile(base, file)
        file.chmod(0o700)
        if name == "unsigned":
            run("/usr/bin/clang", "-arch", "x86_64", str(ROOT / "scripts/macos/tests/peer_fixture.c"), "-o", str(file))
            # x86_64 permits genuinely unsigned code; arm64 requires ad hoc signing.
            run("/usr/bin/codesign", "--remove-signature", str(file))
            continue
        args = ["/usr/bin/codesign", "--force", "--timestamp=none", "--identifier", "ai.envcloak.app"]
        if identity is None:
            args += ["--sign", "-"]
        else:
            chosen = identities[identity]
            args += ["--sign", chosen["sha1"], "--keychain", chosen["keychain"]]
        if runtime:
            args += ["--options", "runtime"]
        if entitlement:
            plist = root / (name + ".plist")
            plist.write_bytes(plistlib.dumps({entitlement: not name.endswith("-false")}))
            args += ["--entitlements", str(plist)]
        if identity is None:
            run(*args, str(file))
        else:
            run(str(root / "sign_peer"), chosen["keychain"], chosen["certificate"], str(file), "ai.envcloak.app", "65536" if runtime else "0", str(plist) if entitlement else "")
            requirement = f'identifier "ai.envcloak.app" and certificate leaf = H"{chosen["sha1"]}"'
            # The leading = selects an inline requirement instead of a file.
            run("/usr/bin/codesign", "--verify", "--strict", "-R", "=" + requirement, str(file))
    # Independent reader already used by gate 19, via Security.framework rather than codesign text.
    run("/usr/bin/swiftc", str(ROOT / "scripts/macos/tests/oracles/codesign_facts.swift"),
        "-o", str(root / "facts"))
    dylib = root / "constructor.c"
    dylib.write_text('#include <fcntl.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
                     '__attribute__((constructor)) static void mark(void) {\n'
                     'const char *p = getenv("EC_CONSTRUCTOR_MARKER"); if (!p) return;\n'
                     'int fd = open(p, O_WRONLY|O_CREAT|O_EXCL, 0600); if (fd >= 0) close(fd); }\n')
    run("/usr/bin/clang", "-dynamiclib", str(dylib), "-o", str(root / "constructor.dylib"))
    # Use Apple's signer independently of sign_peer and the app certificate.
    # Pin the library's signing mode too, rather than relying on clang defaults.
    run("/usr/bin/codesign", "--force", "--timestamp=none", "--sign", "-",
        "--identifier", "ai.envcloak.constructor", str(root / "constructor.dylib"))
    for name, runtime in [("hardened", True), ("plain", False)]:
        file = root / (name + "-oracle")
        run("/usr/bin/clang", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "crates/envcloak-sys/tests/fixtures/dyld_policy.c"), "-o", str(file))
        run("/usr/bin/codesign", "--force", "--timestamp=none", "--sign", "-",
            "--identifier", "ai.envcloak.dyld-oracle",
            *(["--options", "runtime"] if runtime else []), str(file))
        run("/usr/bin/codesign", "--verify", "--strict", str(file))
    # These are public certificate fingerprints, not credentials.
    print(identities[0]["sha1"])


if __name__ == "__main__":
    os.umask(0o077)
    prepare(Path(sys.argv[1]).resolve())
