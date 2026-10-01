#!/usr/bin/env python3
"""Installs the agent hosts the M2 tests drive, pinned (M2 plan task M2-04).

Reads crates/envcloak-e2e/agents/versions.toml and installs each host it
lists into a cache outside every HOME: ENVCLOAK_AGENT_HOSTS, else
<target>/agent-hosts, where <target> is CARGO_TARGET_DIR or the
workspace's target/. Each host goes into its own directory,
<id>-<variant>-<version>-<platform>/, made in a temporary directory first
and renamed into place only once the SHA-256 of its entry file (and of its
download, where versions.toml gives one) equals the pinned value. Nothing
unverified is left in the cache. A host already installed is checked
again and kept.

Methods:
- download: one file from `url`, which is the entry itself;
- tarball: an archive from `url`, its first path component stripped,
  members with absolute paths, `..` or links leaving the directory
  refused;
- npm: `npm ci --prefix <dir>` against the committed lockfile in
  crates/envcloak-e2e/agents/npm/<id>/ (package.json naming exactly
  `<package>` at `<version>`, and package-lock.json with an integrity hash
  for every package in the tree), with install scripts only when
  `scripts = true`.

A host whose entry is a script names its `interpreter` (`node`); one whose
entry starts another program names it in `starts` (relative to the host's
directory) with its SHA-256 in `starts_sha256`, checked like the entry's.

Node.js itself is pinned in versions.toml's [node] table, by version, by
the SHA-256 of the official archive and by that of its bin/node, and
installed first into node-<version>-<platform>/ in the same cache, the
same way (verified, then renamed into place). Every npm install runs that
Node's own npm, and the test harness runs every `interpreter = "node"`
host with that node: nothing depends on a Node found on PATH.

`url` may name {version}, {platform} (darwin-arm64, linux-x64), {os}
(darwin, linux) and {arch} (arm64, x64).

usage: install-agent-hosts.py [--tier 1|2|all] [--host ID[/VARIANT]]...
                              [--platform P] [--print-hashes]
       install-agent-hosts.py --print-cache-dir
--print-hashes downloads and prints the SHA-256 values for the platform
instead of checking them, for a maintainer pinning a new version; it
installs nothing. --print-cache-dir prints the cache directory and exits
(envcloak-testkit checks that its own default is the same one).

Prints one line per host and exits 0 when every host asked for is
installed and verified, 1 otherwise.
"""

import hashlib
import json
import os
import platform as pyplatform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERSIONS = os.path.join(ROOT, "crates", "envcloak-e2e", "agents", "versions.toml")
NPM_LOCKS = os.path.join(ROOT, "crates", "envcloak-e2e", "agents", "npm")


def this_platform():
    system = {"Darwin": "darwin", "Linux": "linux"}.get(pyplatform.system())
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(
        pyplatform.machine().lower()
    )
    if not system or not machine:
        return None
    return "%s-%s" % (system, machine)


def cache_dir():
    given = os.environ.get("ENVCLOAK_AGENT_HOSTS")
    if given:
        return given
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target")
    return os.path.join(target, "agent-hosts")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def expand(template, host, plat):
    os_name, arch = plat.split("-", 1)
    return template.format(version=host["version"], platform=plat, os=os_name, arch=arch)


def per_platform(host, key, plat):
    value = host.get(key)
    if isinstance(value, dict):
        return value.get(plat)
    return value


def fetch(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "envcloak-install-agent-hosts"})
    with urllib.request.urlopen(req, timeout=600) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)


def extract(archive, dest, strip):
    with tarfile.open(archive, "r:*") as tar:
        for m in tar.getmembers():
            parts = [p for p in m.name.split("/") if p not in ("", ".")]
            if any(p == ".." for p in parts) or m.name.startswith("/"):
                raise ValueError("an archive member leaves the directory")
            if len(parts) <= strip:
                continue
            if m.issym() or m.islnk():
                target = m.linkname
                if target.startswith("/"):
                    raise ValueError("an archive link leaves the directory")
                # A symlink is relative to its own directory (Node's
                # bin/npm -> ../lib/...), a hard link to the archive's root;
                # either must land inside what is extracted.
                base = "/".join(parts[strip:-1]) if m.issym() else ""
                landed = os.path.normpath(os.path.join(base, target))
                if m.islnk():
                    landed = os.path.normpath("/".join(
                        [p for p in target.split("/") if p not in ("", ".")][strip:]))
                if landed == ".." or landed.startswith("../") or landed.startswith("/"):
                    raise ValueError("an archive link leaves the directory")
            m.name = "/".join(parts[strip:])
            if m.islnk():
                m.linkname = "/".join([p for p in m.linkname.split("/") if p][strip:])
            tar.extract(m, dest, filter="data")


def label(host):
    return "%s/%s %s" % (host["id"], host["variant"], host["version"])


def node_dir(cache, node, plat):
    return os.path.join(cache, "node-%s-%s" % (node["version"], plat))


def install_node(node, plat, cache, print_hashes):
    """Installs the pinned Node.js into the cache: its archive checked
    against `archive_sha256`, then its bin/node against `sha256`."""
    want_archive = per_platform(node, "archive_sha256", plat)
    want = per_platform(node, "sha256", plat)
    url = per_platform(node, "url", plat)
    if url is None or ((want is None or want_archive is None) and not print_hashes):
        return False, "Node.js is not pinned for %s" % plat
    final = node_dir(cache, node, plat)
    binary = os.path.join("bin", "node")
    if not print_hashes and os.path.isdir(final):
        if sha256_file(os.path.join(final, binary)) == want:
            return True, "already installed, verified"
        return False, "installed copy does not match its pin; remove %s and run again" % final
    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-node-", dir=cache)
    try:
        archive = os.path.join(tmp, ".archive")
        fetch(url.format(version=node["version"]), archive)
        got = sha256_file(archive)
        if print_hashes:
            print("  node archive_sha256 %s = %s" % (plat, got))
        elif got != want_archive:
            return False, "download SHA-256 %s, pinned %s" % (got, want_archive)
        extract(archive, tmp, 1)
        os.unlink(archive)
        got = sha256_file(os.path.join(tmp, binary))
        if print_hashes:
            print("  node sha256 %s = %s" % (plat, got))
            return True, "hashes printed, nothing installed"
        if got != want:
            return False, "bin/node SHA-256 %s, pinned %s" % (got, want)
        os.rename(tmp, final)
        tmp = None
        return True, "installed, verified"
    except (OSError, ValueError, tarfile.TarError) as e:
        return False, "%s" % e
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def install(host, plat, cache, print_hashes, node):
    entry = per_platform(host, "entry", plat)
    want = per_platform(host, "sha256", plat)
    if entry is None:
        return False, "no entry for %s" % plat
    if want is None and not print_hashes:
        return False, "no pinned SHA-256 for %s" % plat
    name = "%s-%s-%s-%s" % (host["id"], host["variant"], host["version"], plat)
    final = os.path.join(cache, name)
    starts = per_platform(host, "starts", plat)
    starts_want = per_platform(host, "starts_sha256", plat)
    if starts is not None and starts_want is None and not print_hashes:
        return False, "no pinned starts_sha256 for %s" % plat

    def verified(base):
        for rel, pinned in ((entry, want), (starts, starts_want)):
            if rel is None:
                continue
            path = os.path.join(base, rel)
            if not os.path.isfile(path) or sha256_file(path) != pinned:
                return False
        return True

    if not print_hashes and os.path.isdir(final):
        if verified(final):
            return True, "already installed, verified"
        return False, "installed copy does not match its pin; remove %s and run again" % final
    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-" + name + "-", dir=cache)
    try:
        method = host["method"]
        if method == "download":
            dest = os.path.join(tmp, entry)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            fetch(expand(host["url"], host, plat), dest)
            os.chmod(dest, 0o755)
        elif method == "tarball":
            archive = os.path.join(tmp, ".archive")
            fetch(expand(host["url"], host, plat), archive)
            got = sha256_file(archive)
            pinned = per_platform(host, "archive_sha256", plat)
            if print_hashes:
                print("  %s archive_sha256 %s = %s" % (label(host), plat, got))
            elif got != pinned:
                return False, "download SHA-256 %s, pinned %s" % (got, pinned)
            extract(archive, tmp, int(host.get("strip", 0)))
            os.unlink(archive)
        elif method == "npm":
            locks = os.path.join(NPM_LOCKS, host["id"])
            try:
                with open(os.path.join(locks, "package.json"), "rb") as f:
                    manifest = json.load(f)
                with open(os.path.join(locks, "package-lock.json"), "rb") as f:
                    lock = json.load(f)
            except (OSError, ValueError) as e:
                return False, "no lockfile for %s: %s" % (host["id"], e)
            if manifest.get("dependencies") != {host["package"]: host["version"]}:
                return False, "%s/package.json does not name %s@%s alone" % (
                    locks, host["package"], host["version"])
            unpinned = [k for k, v in lock.get("packages", {}).items()
                        if k and not v.get("link") and not v.get("integrity")]
            if unpinned:
                return False, "the lockfile pins no integrity for %s" % ", ".join(unpinned[:3])
            for name in ("package.json", "package-lock.json"):
                shutil.copyfile(os.path.join(locks, name), os.path.join(tmp, name))
            # By its real path: npm reads a prefix reached through a link
            # (macOS's /tmp, a `..`) as a link to a package of its own. The
            # pinned Node's own npm, with that Node first on PATH for any
            # install script.
            if node is None:
                return False, "Node.js is not installed for npm hosts"
            npm = os.path.join(node, "lib", "node_modules", "npm", "bin", "npm-cli.js")
            cmd = [os.path.join(node, "bin", "node"), npm, "ci", "--prefix",
                   os.path.realpath(tmp), "--no-audit", "--no-fund", "--loglevel=error"]
            if not host.get("scripts", False):
                cmd.insert(3, "--ignore-scripts")
            env = dict(os.environ)
            env["PATH"] = os.path.join(node, "bin") + os.pathsep + env.get("PATH", "")
            env["npm_config_update_notifier"] = "false"
            r = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if r.returncode != 0:
                return False, "npm install failed: %s" % r.stderr.decode("utf-8", "replace")[-400:]
        else:
            return False, "unknown method %r" % method
        path = os.path.join(tmp, entry)
        if not os.path.isfile(path):
            return False, "the entry %s is missing after install" % entry
        got = sha256_file(path)
        started = None
        if starts is not None:
            if not os.path.isfile(os.path.join(tmp, starts)):
                return False, "the program the entry starts, %s, is missing after install" % starts
            started = sha256_file(os.path.join(tmp, starts))
        if print_hashes:
            print("  %s sha256 %s = %s" % (label(host), plat, got))
            if started is not None:
                print("  %s starts_sha256 %s = %s" % (label(host), plat, started))
            return True, "hashes printed, nothing installed"
        if got != want:
            return False, "entry SHA-256 %s, pinned %s" % (got, want)
        if started is not None and started != starts_want:
            return False, "SHA-256 of %s %s, pinned %s" % (starts, started, starts_want)
        with open(os.path.join(tmp, "installed.json"), "w") as f:
            json.dump({"id": host["id"], "variant": host["variant"], "version": host["version"],
                       "platform": plat, "entry": entry, "sha256": got,
                       "starts": starts, "starts_sha256": started}, f)
        os.rename(tmp, final)
        tmp = None
        return True, "installed, verified"
    except (OSError, ValueError, tarfile.TarError) as e:
        return False, "%s" % e
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    tier = "1"
    only = []
    plat = this_platform()
    print_hashes = False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--tier" and i + 1 < len(argv):
            tier = argv[i + 1]
            i += 2
        elif a == "--host" and i + 1 < len(argv):
            only.append(argv[i + 1])
            i += 2
        elif a == "--platform" and i + 1 < len(argv):
            plat = argv[i + 1]
            i += 2
        elif a == "--print-hashes":
            print_hashes = True
            i += 1
        elif a == "--print-cache-dir" and len(argv) == 2:
            print(cache_dir())
            return 0
        else:
            print(__doc__, file=sys.stderr)
            return 2
    if plat not in ("darwin-arm64", "linux-x64"):
        print("install-agent-hosts: platform %r is not pinned" % plat, file=sys.stderr)
        return 1
    import tomllib  # Python 3.11; --print-cache-dir needs nothing from it

    with open(VERSIONS, "rb") as f:
        doc = tomllib.load(f)
    cache = cache_dir()
    ok = True
    hosts = []
    for host in doc.get("host", []):
        key = "%s/%s" % (host["id"], host["variant"])
        if only and host["id"] not in only and key not in only:
            continue
        if not only and tier != "all" and str(host.get("tier")) != tier:
            continue
        hosts.append(host)
    node = None
    if any(h["method"] == "npm" or h.get("interpreter") == "node" for h in hosts):
        good, why = install_node(doc["node"], plat, cache, print_hashes)
        print("install-agent-hosts: node %s (%s): %s" % (doc["node"]["version"], plat, why))
        ok = ok and good
        if os.path.isdir(node_dir(cache, doc["node"], plat)):
            node = node_dir(cache, doc["node"], plat)
    for host in hosts:
        good, why = install(host, plat, cache, print_hashes, node)
        print("install-agent-hosts: %s (%s): %s" % (label(host), plat, why))
        ok = ok and good
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
