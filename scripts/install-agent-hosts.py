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
the SHA-256 of the official archive, by that of its bin/node and by a
digest of its whole extracted tree (`tree_sha256`: every path, file
contents and link target, so its npm too), and installed first into
node-<version>-<platform>/ in the same cache, the same way (verified,
then renamed into place). A copy already there is checked whole again
before it is used. Every npm install runs that Node's own npm, and only
once this run has verified it: when Node fails its pin check, no npm host
is installed and nothing is run. The test harness runs every
`interpreter = "node"` host with that node: nothing depends on a Node
found on PATH.

`url` may name {version}, {platform} (darwin-arm64, linux-x64), {os}
(darwin, linux) and {arch} (arm64, x64).

--mcp-client also installs the official MCP TypeScript SDK that M2-06's
tests drive `envcloak mcp` with (versions.toml's [mcp_client] table: its
package and version), with `npm ci --ignore-scripts` from the lockfile in
crates/envcloak-e2e/mcp-client/ (an integrity hash for every package in
the tree), under the Node this run verified, into
mcp-client-<version>-<lockfile digest>-<platform>/ in the same cache. It is
kept only when the installed package's version is the pinned one.

usage: install-agent-hosts.py [--tier 1|2|all] [--host ID[/VARIANT]]...
                              [--mcp-client] [--platform P] [--print-hashes]
       install-agent-hosts.py --print-cache-dir
       install-agent-hosts.py --self-test
--print-hashes downloads and prints the SHA-256 values for the platform
instead of checking them, for a maintainer pinning a new version; it
installs nothing, and runs npm only with a cached Node that matches the
pins as they stand. --print-cache-dir prints the cache directory and exits
(envcloak-testkit checks that its own default is the same one).
--self-test runs the installer's own checks on synthetic pins in a
temporary cache, with no network and nothing run (CI runs it).

Prints one line per host and exits 0 when every host asked for is
installed and verified, 1 otherwise.
"""

import contextlib
import hashlib
import io
import json
import os
import platform as pyplatform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERSIONS = os.path.join(ROOT, "crates", "envcloak-e2e", "agents", "versions.toml")
NPM_LOCKS = os.path.join(ROOT, "crates", "envcloak-e2e", "agents", "npm")
MCP_CLIENT = os.path.join(ROOT, "crates", "envcloak-e2e", "mcp-client")


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


def tree_sha256(root):
    """A digest of the tree at `root`: each entry's path below it, its kind,
    and a file's SHA-256 or a link's target, in path order, so the same
    tree gives the same digest wherever it was extracted. Links are not
    followed; modes and times are left out. Any entry that cannot be read
    raises."""

    def fail(e):
        raise e

    rels = []
    for top, dirs, files in os.walk(root, onerror=fail):
        for name in dirs + files:
            rels.append(os.path.relpath(os.path.join(top, name), root))
    h = hashlib.sha256()
    for rel in sorted(rels, key=os.fsencode):
        path = os.path.join(root, rel)
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode):
            kind, extra = b"l", os.fsencode(os.readlink(path))
        elif stat.S_ISDIR(mode):
            kind, extra = b"d", b""
        elif stat.S_ISREG(mode):
            kind, extra = b"f", sha256_file(path).encode()
        else:
            kind, extra = b"o", b""
        name = os.fsencode(rel)
        h.update(b"%s %d:%s %d:%s\0" % (kind, len(name), name, len(extra), extra))
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


NODE_BINARY = os.path.join("bin", "node")


def node_matches(path, want, want_tree):
    """Why the Node tree at `path` is not the pinned one, or None when its
    bin/node and its whole tree both match their pins."""
    if want is None or want_tree is None:
        return "not pinned"
    try:
        got = sha256_file(os.path.join(path, NODE_BINARY))
        if got != want:
            return "bin/node SHA-256 %s, pinned %s" % (got, want)
        got = tree_sha256(path)
        if got != want_tree:
            return "tree SHA-256 %s, pinned %s" % (got, want_tree)
    except OSError as e:
        return "%s" % e
    return None


def install_node(node, plat, cache, print_hashes):
    """Installs the pinned Node.js into the cache: its archive checked
    against `archive_sha256`, then its bin/node against `sha256` and its
    whole tree against `tree_sha256`. Returns (ok, why, path), where
    `path` is the Node directory only when this run has verified it whole
    against the pins, else None: nothing uses a Node that failed its check
    or was not checked. With print_hashes it prints the three values of a
    fresh download and installs nothing; `path` is then a cached copy only
    when it matches the pins as they stand."""
    want_archive = per_platform(node, "archive_sha256", plat)
    want = per_platform(node, "sha256", plat)
    want_tree = per_platform(node, "tree_sha256", plat)
    url = per_platform(node, "url", plat)
    pinned = None not in (want, want_archive, want_tree)
    if url is None or not (pinned or print_hashes):
        return False, "Node.js is not pinned for %s" % plat, None
    final = node_dir(cache, node, plat)
    if not print_hashes and os.path.lexists(final):
        if os.path.islink(final) or not os.path.isdir(final):
            return False, "%s is not a directory; remove it and run again" % final, None
        why = node_matches(final, want, want_tree)
        if why is None:
            return True, "already installed, verified", final
        return False, "installed copy does not match its pin (%s); remove %s and run again" % (
            why, final), None
    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-node-", dir=cache)
    try:
        archive = os.path.join(tmp, ".archive")
        fetch(url.format(version=node["version"]), archive)
        got = sha256_file(archive)
        if print_hashes:
            print("  node archive_sha256 %s = %s" % (plat, got))
        elif got != want_archive:
            return False, "download SHA-256 %s, pinned %s" % (got, want_archive), None
        extract(archive, tmp, 1)
        os.unlink(archive)
        if print_hashes:
            print("  node sha256 %s = %s" % (plat, sha256_file(os.path.join(tmp, NODE_BINARY))))
            print("  node tree_sha256 %s = %s" % (plat, tree_sha256(tmp)))
            cached = None
            if pinned and os.path.isdir(final) and not os.path.islink(final):
                if node_matches(final, want, want_tree) is None:
                    cached = final
            return True, "hashes printed, nothing installed", cached
        why = node_matches(tmp, want, want_tree)
        if why is not None:
            return False, why, None
        os.rename(tmp, final)
        tmp = None
        return True, "installed, verified", final
    except (OSError, ValueError, tarfile.TarError) as e:
        return False, "%s" % e, None
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
    if host["method"] == "npm" and node is None:
        return False, "not installed: no Node.js this run verified against its pins"
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
            # pinned Node's own npm (both verified whole this run), with
            # that Node first on PATH for any install script.
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


def mcp_client_dir(cache, client, plat, lock_digest):
    return os.path.join(cache, "mcp-client-%s-%s-%s" % (client["version"], lock_digest[:16], plat))


def install_mcp_client(client, plat, cache, node):
    """Installs the pinned MCP SDK client (see the module documentation)
    with `npm ci --ignore-scripts` under `node`, the Node this run
    verified (None: nothing is run). Returns (ok, why)."""
    try:
        with open(os.path.join(MCP_CLIENT, "package.json"), "rb") as f:
            manifest = json.load(f)
        lock_path = os.path.join(MCP_CLIENT, "package-lock.json")
        with open(lock_path, "rb") as f:
            lock = json.load(f)
        digest = sha256_file(lock_path)
    except (OSError, ValueError) as e:
        return False, "no lockfile for the MCP client: %s" % e
    if manifest.get("dependencies") != {client["package"]: client["version"]}:
        return False, "%s/package.json does not name %s@%s alone" % (
            MCP_CLIENT, client["package"], client["version"])
    unpinned = [k for k, v in lock.get("packages", {}).items()
                if k and not v.get("link") and not v.get("integrity")]
    if unpinned:
        return False, "the MCP client's lockfile pins no integrity for %s" % ", ".join(unpinned[:3])
    final = mcp_client_dir(cache, client, plat, digest)

    def verified(base):
        try:
            with open(os.path.join(base, "installed.json"), "rb") as f:
                stamp = json.load(f)
            with open(os.path.join(base, "node_modules", client["package"], "package.json"),
                      "rb") as f:
                version = json.load(f).get("version")
        except (OSError, ValueError):
            return False
        return stamp.get("lock_sha256") == digest and version == client["version"]

    if os.path.lexists(final):
        if not os.path.islink(final) and os.path.isdir(final) and verified(final):
            return True, "already installed, verified"
        return False, "installed copy does not match its pin; remove %s and run again" % final
    if node is None:
        return False, "not installed: no Node.js this run verified against its pins"
    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-mcp-client-", dir=cache)
    try:
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(os.path.join(MCP_CLIENT, name), os.path.join(tmp, name))
        npm = os.path.join(node, "lib", "node_modules", "npm", "bin", "npm-cli.js")
        cmd = [os.path.join(node, "bin", "node"), npm, "ci", "--ignore-scripts", "--prefix",
               os.path.realpath(tmp), "--no-audit", "--no-fund", "--loglevel=error"]
        env = dict(os.environ)
        env["PATH"] = os.path.join(node, "bin") + os.pathsep + env.get("PATH", "")
        env["npm_config_update_notifier"] = "false"
        r = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if r.returncode != 0:
            return False, "npm install failed: %s" % r.stderr.decode("utf-8", "replace")[-400:]
        with open(os.path.join(tmp, "installed.json"), "w") as f:
            json.dump({"package": client["package"], "version": client["version"],
                       "platform": plat, "lock_sha256": digest}, f)
        if not verified(tmp):
            return False, "the installed %s is not version %s" % (
                client["package"], client["version"])
        os.rename(tmp, final)
        tmp = None
        return True, "installed, verified"
    except (OSError, ValueError) as e:
        return False, "%s" % e
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    tier = "1"
    only = []
    plat = this_platform()
    print_hashes = False
    mcp_client = False
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
        elif a == "--mcp-client":
            mcp_client = True
            i += 1
        elif a == "--print-cache-dir" and len(argv) == 2:
            print(cache_dir())
            return 0
        elif a == "--self-test" and len(argv) == 2:
            return self_test()
        else:
            print(__doc__, file=sys.stderr)
            return 2
    if plat not in ("darwin-arm64", "linux-x64"):
        print("install-agent-hosts: platform %r is not pinned" % plat, file=sys.stderr)
        return 1
    import tomllib  # Python 3.11; --print-cache-dir needs nothing from it

    with open(VERSIONS, "rb") as f:
        doc = tomllib.load(f)
    return run(doc, plat, cache_dir(), tier, only, print_hashes, mcp_client)


def run(doc, plat, cache, tier, only, print_hashes, mcp_client=False):
    """Installs the hosts of `doc` (versions.toml) asked for, and the MCP
    client with `mcp_client`; the exit status."""
    ok = True
    hosts = []
    for host in doc.get("host", []):
        key = "%s/%s" % (host["id"], host["variant"])
        if only and host["id"] not in only and key not in only:
            continue
        if not only and tier != "all" and str(host.get("tier")) != tier:
            continue
        hosts.append(host)
    # The Node npm runs under: only one this run verified whole against its
    # pins, never one taken from a directory because it is there.
    node = None
    if mcp_client or any(h["method"] == "npm" or h.get("interpreter") == "node" for h in hosts):
        good, why, node = install_node(doc["node"], plat, cache, print_hashes)
        print("install-agent-hosts: node %s (%s): %s" % (doc["node"]["version"], plat, why))
        ok = ok and good
    for host in hosts:
        good, why = install(host, plat, cache, print_hashes, node)
        print("install-agent-hosts: %s (%s): %s" % (label(host), plat, why))
        ok = ok and good
    if mcp_client and not print_hashes:
        client = doc["mcp_client"]
        good, why = install_mcp_client(client, plat, cache, node)
        print("install-agent-hosts: mcp client %s@%s (%s): %s" % (
            client["package"], client["version"], plat, why))
        ok = ok and good
    return 0 if ok else 1


def self_test():
    """The installer's own checks, on synthetic pins in a temporary cache:
    downloads come from local files (any other URL fails the test) and
    every subprocess is recorded, never run. A Node that fails its pin
    check (its bin/node, or any other file, its npm included) is never run
    and no npm host is installed; a verified one runs `npm ci` once per
    npm host. The exit status: 0 when every case passes."""
    global fetch, NPM_LOCKS, MCP_CLIENT
    real_fetch, real_locks, real_run = fetch, NPM_LOCKS, subprocess.run
    plat = "linux-x64"
    failures = []
    with tempfile.TemporaryDirectory(prefix="ec-install-test-") as top:
        # A Node archive: node-v<version>-<platform>/ with bin/node, npm and
        # a link, as nodejs.org's are laid out.
        src = os.path.join(top, "src", "node-v1.2.3-linux-x64")
        for rel, data in (("bin/node", b"#!/bin/false\nnode\n"),
                          ("lib/node_modules/npm/bin/npm-cli.js", b"// npm\n"),
                          ("lib/node_modules/npm/lib/cli.js", b"// cli\n")):
            os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
            with open(os.path.join(src, rel), "wb") as f:
                f.write(data)
        os.symlink("../lib/node_modules/npm/bin/npm-cli.js", os.path.join(src, "bin", "npm"))
        archive = os.path.join(top, "node.tar.gz")
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(src, arcname="node-v1.2.3-linux-x64")
        locks = os.path.join(top, "locks", "fake-host")
        os.makedirs(locks)
        with open(os.path.join(locks, "package.json"), "w") as f:
            json.dump({"dependencies": {"fake-host": "4.5.6"}}, f)
        with open(os.path.join(locks, "package-lock.json"), "w") as f:
            json.dump({"packages": {"": {}, "node_modules/fake-host": {"integrity": "sha512-x"}}}, f)
        entry = b"// the fake host\n"
        node = {"version": "1.2.3",
                "url": {plat: "https://node.invalid/node-{version}.tar.gz"},
                "archive_sha256": {plat: sha256_file(archive)},
                "sha256": {plat: hashlib.sha256(b"#!/bin/false\nnode\n").hexdigest()},
                "tree_sha256": {plat: tree_sha256(src)}}
        host = {"id": "fake-host", "variant": "npm", "tier": 2, "version": "4.5.6",
                "method": "npm", "package": "fake-host",
                "entry": "node_modules/fake-host/cli.js",
                "sha256": {plat: hashlib.sha256(entry).hexdigest()}}
        downloads = {"https://node.invalid/node-1.2.3.tar.gz": archive}
        dispatched, names = [], []
        # The MCP client's lockfile, and the version its `npm ci` installs.
        client = {"package": "fake-sdk", "version": "7.8.9"}
        client_locks = os.path.join(top, "mcp-client")
        os.makedirs(client_locks)
        with open(os.path.join(client_locks, "package.json"), "w") as f:
            json.dump({"dependencies": {"fake-sdk": "7.8.9"}}, f)
        with open(os.path.join(client_locks, "package-lock.json"), "w") as f:
            json.dump({"packages": {"": {}, "node_modules/fake-sdk": {"integrity": "sha512-y"}}}, f)
        installs_version = ["7.8.9"]

        def local_fetch(url, dest):
            if url not in downloads:
                raise OSError("no network in the self-test: %s" % url)
            shutil.copyfile(downloads[url], dest)

        def spy(cmd, **kwargs):
            # `npm ci` as it would end: the host's entry in the prefix, and
            # the MCP client's package at the version the case says.
            dispatched.append(list(cmd))
            prefix = cmd[cmd.index("--prefix") + 1]
            path = os.path.join(prefix, host["entry"])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(entry)
            sdk = os.path.join(prefix, "node_modules", client["package"])
            os.makedirs(sdk, exist_ok=True)
            with open(os.path.join(sdk, "package.json"), "w") as f:
                json.dump({"version": installs_version[0]}, f)
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        def case(name, prepare, want_status, want_dispatches, want_host, doc_node=node):
            cache = os.path.join(top, "cache-%d" % len(names))
            names.append(name)
            os.makedirs(cache)
            prepare(cache)
            del dispatched[:]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = run({"node": doc_node, "host": [host]}, plat, cache, "all", [], False)
            got_host = os.path.isdir(os.path.join(cache, "fake-host-npm-4.5.6-" + plat))
            nodes = {c[0] for c in dispatched}
            want_node = {os.path.join(node_dir(cache, node, plat), "bin", "node")}
            problems = []
            if status != want_status:
                problems.append("exit %d, wanted %d" % (status, want_status))
            if len(dispatched) != want_dispatches:
                problems.append("%d npm runs, wanted %d" % (len(dispatched), want_dispatches))
            if dispatched and nodes != want_node:
                problems.append("npm ran under %s" % sorted(nodes))
            if got_host != want_host:
                problems.append("host installed: %s" % got_host)
            if problems:
                failures.append(name)
            print("self-test: %s: %s" % (name, "; ".join(problems) or "ok"))
            for line in out.getvalue().splitlines():
                print("    " + line)

        def copy_node(cache, change=None):
            dest = node_dir(cache, node, plat)
            shutil.copytree(src, dest, symlinks=True)
            if change:
                with open(os.path.join(dest, change), "ab") as f:
                    f.write(b"changed\n")

        def client_case(name, prepare, want_status, want_dispatches, want_client,
                        version="7.8.9"):
            """`--mcp-client` with no host: the client is installed only
            under a Node this run verified, and kept only at its pinned
            version."""
            cache = os.path.join(top, "cache-%d" % len(names))
            names.append(name)
            os.makedirs(cache)
            prepare(cache)
            del dispatched[:]
            installs_version[0] = version
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = run({"node": node, "host": [], "mcp_client": client}, plat, cache,
                             "all", [], False, True)
            got = any(n.startswith("mcp-client-7.8.9-") for n in os.listdir(cache))
            nodes = {c[0] for c in dispatched}
            want_node = {os.path.join(node_dir(cache, node, plat), "bin", "node")}
            problems = []
            if status != want_status:
                problems.append("exit %d, wanted %d" % (status, want_status))
            if len(dispatched) != want_dispatches:
                problems.append("%d npm runs, wanted %d" % (len(dispatched), want_dispatches))
            if dispatched and nodes != want_node:
                problems.append("npm ran under %s" % sorted(nodes))
            if dispatched and any("--ignore-scripts" not in c for c in dispatched):
                problems.append("npm ran install scripts")
            if got != want_client:
                problems.append("client installed: %s" % got)
            if problems:
                failures.append(name)
            print("self-test: %s: %s" % (name, "; ".join(problems) or "ok"))
            for line in out.getvalue().splitlines():
                print("    " + line)

        real_client = MCP_CLIENT
        fetch, NPM_LOCKS, subprocess.run = local_fetch, os.path.dirname(locks), spy
        MCP_CLIENT = client_locks
        try:
            client_case("mcp client, verified cached node", copy_node, 0, 1, True)
            client_case("mcp client, cached node whose bin/node is not the pinned one",
                        lambda c: copy_node(c, "bin/node"), 1, 0, False)
            client_case("mcp client, npm installs another version", copy_node, 1, 1, False,
                        version="7.8.10")
            case("verified cached node, uncached npm host", copy_node, 0, 1, True)
            case("no cached node, download verified", lambda c: None, 0, 1, True)
            case("cached node whose bin/node is not the pinned one, uncached npm host",
                 lambda c: copy_node(c, "bin/node"), 1, 0, False)
            case("cached node whose npm is not the pinned one, uncached npm host",
                 lambda c: copy_node(c, "lib/node_modules/npm/bin/npm-cli.js"), 1, 0, False)
            case("cached node with a file added, uncached npm host",
                 lambda c: (copy_node(c), open(os.path.join(
                     node_dir(c, node, plat), "lib", "extra.js"), "wb").close()), 1, 0, False)
            case("no cached node, download not the pinned archive", lambda c: None, 1, 0, False,
                 dict(node, archive_sha256={plat: "0" * 64}))
            case("no cached node, extracted tree not the pinned one", lambda c: None, 1, 0, False,
                 dict(node, tree_sha256={plat: "0" * 64}))
            case("node not pinned for the platform", lambda c: None, 1, 0, False,
                 dict(node, tree_sha256={}))
        finally:
            fetch, NPM_LOCKS, subprocess.run = real_fetch, real_locks, real_run
            MCP_CLIENT = real_client
    if failures:
        print("install-agent-hosts: self-test failed: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    print("install-agent-hosts: self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
