#!/usr/bin/env python3
"""Build pinned runtime oracles locally in the supplied cache, never install."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import platform
import tarfile
import urllib.request
import zipfile

# Upstream release archives, verified before extraction on every invocation.
SOURCES = (
    ("php-8.4.5", "https://www.php.net/distributions/php-8.4.5.tar.xz",
     "0d3270bbce4d9ec617befce52458b763fd461d475f1fe2ed878bb8573faed327",
     ["--disable-all", "--enable-cli", "--disable-cgi", "--disable-phpdbg", "--without-pear"], "sapi/cli/php"),
    ("Python-3.14.0", "https://www.python.org/ftp/python/3.14.0/Python-3.14.0.tar.xz",
     "2299dae542d395ce3883aca00d3c910307cd68e0b2f7336098c8e7b7eee9f3e9",
     ["--with-pydebug", "--without-ensurepip", "--disable-test-modules"], "python"),
    ("package", "https://registry.npmjs.org/npm/-/npm-11.19.0.tgz",
     "31e9770f7dc71119a58509353b27917557aaf0ac9b5ef1a0465ee7d8ec67ae75",
     [], "bin/npm-cli.js"),
    # LuaJIT 2.1 has rolling releases only: a pinned commit's archive. It
    # builds with make alone (flags None), and needs a deployment target on
    # macOS.
    ("LuaJIT-c6ffc141a8762b41703f9287d63d93622a13dd8f",
     "https://github.com/LuaJIT/LuaJIT/archive/c6ffc141a8762b41703f9287d63d93622a13dd8f.tar.gz",
     "6e5fec07750add912e7c3eae0c194d24cd6d023714e1f04a0298a5b4819e4457",
     None, "src/luajit"),
    # Ruby 3.4.7: its option parser (ruby.c) is the oracle; the binary runs
    # from the build tree, without its standard library installed.
    ("ruby-3.4.7", "https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.7.tar.gz",
     "23815a6d095696f7919090fdc3e2f9459b2c83d57224b2e446ce1f5f7333ef36",
     ["--disable-install-doc"], "ruby"),
)

# Deno ships as a binary per platform: its release zip, verified before
# extraction on every invocation. Deno 2.9.7.
DENO_VERSION = "2.9.7"
DENO = {
    ("Darwin", "arm64"): ("deno-aarch64-apple-darwin.zip",
                          "5cd46d6268f6f78f5d88bdc7159d20bd44cdaa4b3303474839f87ec6fe7ae25c"),
    ("Darwin", "x86_64"): ("deno-x86_64-apple-darwin.zip",
                           "95daaff11c116a52ad54785e7914c8e9c9cdcaba793c5ed929c74ca2d8e6259a"),
    ("Linux", "x86_64"): ("deno-x86_64-unknown-linux-gnu.zip",
                          "c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490"),
    ("Linux", "aarch64"): ("deno-aarch64-unknown-linux-gnu.zip",
                           "c832298b1ad4422481334855f6003e0f54145762c5a134f20a489511d2f65bbf"),
}


def provision_deno(root):
    name, digest = DENO[(platform.system(), platform.machine())]
    archive = root / name
    if not archive.exists():
        url = f"https://github.com/denoland/deno/releases/download/v{DENO_VERSION}/{name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("archive digest mismatch: deno")
    target = root / f"deno-{DENO_VERSION}"
    binary = target / "deno"
    if not binary.is_file():
        target.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as contents:
            if contents.namelist() != ["deno"]:
                raise ValueError("unexpected deno archive contents")
            contents.extract("deno", target)
        binary.chmod(0o755)
    return binary


def provision(root):
    root.mkdir(parents=True, exist_ok=True)
    binaries = []
    for name, url, digest, flags, binary in SOURCES:
        archive = root / url.rsplit("/", 1)[1]
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise ValueError(f"archive digest mismatch: {name}")
        source = root / name
        if not source.exists():
            with tarfile.open(archive) as contents:
                contents.extractall(root, filter="data")
        def built_binary():
            plain = source / binary
            # CPython uses .exe on a case-insensitive filesystem because
            # its source already has a Python directory.
            return plain if plain.is_file() else source / (binary + ".exe")

        stamp = source / ".envcloak-oracle-build"
        fingerprint = json.dumps([digest, flags])
        if flags != [] and (not stamp.exists() or stamp.read_text() != fingerprint or not built_binary().is_file()):
            if flags is not None:
                subprocess.run(["./configure", *flags], cwd=source, check=True)
            env = dict(os.environ)
            env.setdefault("MACOSX_DEPLOYMENT_TARGET", "11.0")
            subprocess.run(["make", "-j3"], cwd=source, check=True, env=env)
            stamp.write_text(fingerprint)
        if not built_binary().is_file():
            raise ValueError(f"runtime missing: {name}")
        binaries.append(built_binary())
    # npm's test clears PATH. Give it a private bin directory with the Node
    # selected by CI, and no access to any user's global npm configuration.
    node = shutil.which("node")
    if not node or subprocess.check_output([node, "--version"], text=True).strip() != "v26.7.0":
        raise ValueError("Node 26.7.0 required")
    bindir = root / "bin"
    bindir.mkdir(exist_ok=True)
    for name, target in (("npm", binaries[2]), ("node", Path(node).resolve())):
        link = bindir / name
        if link.is_symlink():
            link.unlink()
        link.symlink_to(target)
    deno = provision_deno(root)
    return dict(zip(
        ("ENVCLOAK_PHP_ORACLE", "ENVCLOAK_PYTHON_DEBUG_ORACLE", "ENVCLOAK_NPM_ORACLE", "ENVCLOAK_LUAJIT_ORACLE",
         "ENVCLOAK_RUBY_ORACLE", "ENVCLOAK_NODE_ORACLE", "ENVCLOAK_DENO_ORACLE"),
        (binaries[0], binaries[1], bindir / "npm", binaries[3], binaries[4], bindir / "node", deno)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    args = parser.parse_args()
    paths = provision(args.cache.resolve())
    lines = "".join(f"{name}={path}\n" for name, path in paths.items())
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as environment:
            environment.write(lines)
    print(lines, end="")


if __name__ == "__main__":
    main()
