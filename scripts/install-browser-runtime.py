#!/usr/bin/env python3
"""Installs and verifies the pinned Node.js, @playwright/mcp browser-helper
dependencies, and Chrome for Testing build (M2b-02, D-29, D-34, Q-06).

Reads integrations/browser/versions.toml and installs each component into the
shared host cache outside every HOME: ENVCLOAK_AGENT_HOSTS, else
<target>/agent-hosts, where <target> is CARGO_TARGET_DIR or the workspace's
target/:
- node-<version>-<platform>/
- browser-helper-<version>-<platform>/
- chrome-for-testing-<version>-<platform>/

Each directory is built in a temporary directory inside the cache, verified by
SHA-256 against integrations/browser/versions.toml (and checked on macOS to
ensure com.apple.quarantine is absent), and renamed into place only after all
checks pass.
"""

import argparse
import hashlib
import json
import os
import platform as pyplatform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERSIONS = os.path.join(ROOT, "integrations", "browser", "versions.toml")
HELPER_SRC = os.path.join(ROOT, "integrations", "browser-helper")


def this_platform():
    system = {"Darwin": "darwin", "Linux": "linux"}.get(pyplatform.system())
    machine = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "x64",
        "amd64": "x64",
    }.get(pyplatform.machine().lower())
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


def fetch(url, dest):
    req = urllib.request.Request(
        url, headers={"User-Agent": "envcloak-install-browser-runtime"}
    )
    with urllib.request.urlopen(req, timeout=600) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)


def extract_tar(archive, dest, strip):
    with tarfile.open(archive, "r:*") as tar:
        for m in tar.getmembers():
            parts = [p for p in m.name.split("/") if p not in ("", ".")]
            if any(p == ".." for p in parts) or m.name.startswith("/"):
                raise ValueError("archive member leaves destination directory")
            if len(parts) <= strip:
                continue
            if m.issym() or m.islnk():
                target = m.linkname
                if target.startswith("/"):
                    raise ValueError("archive link leaves destination directory")
                base = "/".join(parts[strip:-1]) if m.issym() else ""
                landed = os.path.normpath(os.path.join(base, target))
                if m.islnk():
                    landed = os.path.normpath(
                        "/".join(
                            [p for p in target.split("/") if p not in ("", ".")][
                                strip:
                            ]
                        )
                    )
                if (
                    landed == ".."
                    or landed.startswith("../")
                    or landed.startswith("/")
                ):
                    raise ValueError("archive link leaves destination directory")
            m.name = "/".join(parts[strip:])
            if m.islnk():
                m.linkname = "/".join(
                    [p for p in m.linkname.split("/") if p][strip:]
                )
            tar.extract(m, dest, filter="data")


def extract_zip(archive, dest):
    with zipfile.ZipFile(archive, "r") as zf:
        for info in zf.infolist():
            parts = [p for p in info.filename.split("/") if p not in ("", ".")]
            if not parts or any(p == ".." for p in parts) or info.filename.startswith("/"):
                raise ValueError("zip member leaves destination directory")
            rel_path = os.path.join(dest, *parts)
            unix_attr = info.external_attr >> 16
            is_symlink = stat.S_ISLNK(unix_attr)
            if is_symlink:
                link_target = zf.read(info).decode("utf-8")
                if link_target.startswith("/"):
                    raise ValueError("zip symlink target is absolute")
                landed = os.path.normpath(
                    os.path.join(os.path.dirname("/".join(parts)), link_target)
                )
                if landed == ".." or landed.startswith("../"):
                    raise ValueError("zip symlink leaves destination directory")
                os.makedirs(os.path.dirname(rel_path), exist_ok=True)
                os.symlink(link_target, rel_path)
            elif info.is_dir():
                os.makedirs(rel_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(rel_path), exist_ok=True)
                with zf.open(info, "r") as src, open(rel_path, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                if unix_attr:
                    os.chmod(rel_path, unix_attr & 0o777)


def ensure_node(node_cfg, plat, cache):
    version = node_cfg["version"]
    want_bin = node_cfg["sha256"][plat]
    want_tree = node_cfg.get("tree_sha256", {}).get(plat)
    final = os.path.join(cache, "node-%s-%s" % (version, plat))
    node_bin = os.path.join(final, "bin", "node")

    if os.path.isdir(final) and not os.path.islink(final):
        if os.path.isfile(node_bin) and sha256_file(node_bin) == want_bin:
            if want_tree is None or tree_sha256(final) == want_tree:
                print("node %s (%s): already installed, verified" % (version, plat))
                return final
        raise RuntimeError(
            "cached Node at %s failed pin verification; remove it and retry" % final
        )

    url = node_cfg["url"][plat].format(version=version)
    want_archive = node_cfg["archive_sha256"][plat]
    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-node-", dir=cache)
    try:
        archive = os.path.join(tmp, "node.archive")
        fetch(url, archive)
        got_arch = sha256_file(archive)
        if got_arch != want_archive:
            raise RuntimeError(
                "Node archive SHA-256 mismatch: got %s, expected %s"
                % (got_arch, want_archive)
            )
        stage = os.path.join(tmp, "stage")
        os.makedirs(stage, exist_ok=True)
        extract_tar(archive, stage, 1)
        staged_bin = os.path.join(stage, "bin", "node")
        got_bin = sha256_file(staged_bin)
        if got_bin != want_bin:
            raise RuntimeError(
                "Node binary SHA-256 mismatch: got %s, expected %s"
                % (got_bin, want_bin)
            )
        if want_tree is not None:
            got_tree = tree_sha256(stage)
            if got_tree != want_tree:
                raise RuntimeError(
                    "Node tree SHA-256 mismatch: got %s, expected %s"
                    % (got_tree, want_tree)
                )
        os.replace(stage, final)
        print("node %s (%s): installed and verified" % (version, plat))
        return final
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verify_helper_dir(helper_root, helper_cfg):
    entry = os.path.join(helper_root, helper_cfg["entry"])
    bundle = os.path.join(helper_root, helper_cfg["core_bundle"])
    mcp_pkg = os.path.join(helper_root, "node_modules", "@playwright", "mcp", "package.json")
    pw_pkg = os.path.join(helper_root, "node_modules", "playwright", "package.json")
    if not (os.path.isfile(entry) and os.path.isfile(bundle)):
        return "missing entry or core_bundle"
    if sha256_file(entry) != helper_cfg["entry_sha256"]:
        return "entry SHA-256 mismatch"
    if sha256_file(bundle) != helper_cfg["core_bundle_sha256"]:
        return "core_bundle SHA-256 mismatch"
    try:
        with open(mcp_pkg, "r", encoding="utf-8") as f:
            mcp_v = json.load(f).get("version")
        with open(pw_pkg, "r", encoding="utf-8") as f:
            pw_v = json.load(f).get("version")
    except OSError as e:
        return str(e)
    if mcp_v != helper_cfg["version"] or pw_v != helper_cfg["playwright_version"]:
        return "package version mismatch (%s, %s)" % (mcp_v, pw_v)
    return None


def ensure_browser_helper(helper_cfg, node_root, plat, cache, helper_src=HELPER_SRC):
    version = helper_cfg["version"]
    final = os.path.join(cache, "browser-helper-%s-%s" % (version, plat))
    if os.path.isdir(final) and not os.path.islink(final):
        err = verify_helper_dir(final, helper_cfg)
        if err is None:
            print("browser-helper %s (%s): already installed, verified" % (version, plat))
            return final
        raise RuntimeError(
            "cached browser-helper at %s failed verification (%s)" % (final, err)
        )

    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-bhelper-", dir=cache)
    try:
        stage = os.path.join(tmp, "stage")
        os.makedirs(stage, exist_ok=True)
        shutil.copy2(os.path.join(helper_src, "package.json"), os.path.join(stage, "package.json"))
        shutil.copy2(
            os.path.join(helper_src, "package-lock.json"),
            os.path.join(stage, "package-lock.json"),
        )
        node_bin_dir = os.path.join(node_root, "bin")
        npm_cli = os.path.join(node_root, "lib", "node_modules", "npm", "bin", "npm-cli.js")
        node_exe = os.path.join(node_bin_dir, "node")
        npm_cache = os.path.join(tmp, "npm-cache")
        env = {
            "HOME": tmp,
            "TMPDIR": tmp,
            "PATH": "%s:/usr/bin:/bin" % node_bin_dir,
            "npm_config_cache": npm_cache,
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
        }
        subprocess.run(
            [
                node_exe,
                npm_cli,
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            cwd=stage,
            env=env,
            check=True,
        )
        err = verify_helper_dir(stage, helper_cfg)
        if err is not None:
            raise RuntimeError("installed browser-helper failed verification: %s" % err)
        os.replace(stage, final)
        print("browser-helper %s (%s): installed and verified" % (version, plat))
        return final
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_macos_no_quarantine(path):
    if pyplatform.system() != "Darwin":
        return
    res = subprocess.run(
        ["/usr/bin/xattr", "-l", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if "com.apple.quarantine" in res.stdout:
        raise RuntimeError("%s carries com.apple.quarantine" % path)


def ensure_chrome(chrome_cfg, plat, cache):
    version = chrome_cfg["version"]
    entry_rel = chrome_cfg["entry"][plat]
    want_sha = chrome_cfg["sha256"][plat]
    want_archive_sha = chrome_cfg["archive_sha256"][plat]
    url = chrome_cfg["url"][plat]
    final = os.path.join(cache, "chrome-for-testing-%s-%s" % (version, plat))
    entry_path = os.path.join(final, entry_rel)

    if os.path.isdir(final) and not os.path.islink(final):
        if os.path.isfile(entry_path) and sha256_file(entry_path) == want_sha:
            check_macos_no_quarantine(entry_path)
            print("chrome-for-testing %s (%s): already installed, verified" % (version, plat))
            return final
        raise RuntimeError(
            "cached chrome-for-testing at %s failed pin verification" % final
        )

    os.makedirs(cache, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-chrome-", dir=cache)
    try:
        archive = os.path.join(tmp, "chrome.zip")
        fetch(url, archive)
        got_arch = sha256_file(archive)
        if got_arch != want_archive_sha:
            raise RuntimeError(
                "Chrome archive SHA-256 mismatch: got %s, expected %s"
                % (got_arch, want_archive_sha)
            )
        stage = os.path.join(tmp, "stage")
        os.makedirs(stage, exist_ok=True)
        extract_zip(archive, stage)
        if pyplatform.system() == "Darwin":
            subprocess.run(["/usr/bin/xattr", "-cr", stage], check=False)
        staged_entry = os.path.join(stage, entry_rel)
        if not os.path.isfile(staged_entry):
            raise RuntimeError("missing %s in extracted archive" % entry_rel)
        got_sha = sha256_file(staged_entry)
        if got_sha != want_sha:
            raise RuntimeError(
                "Chrome binary SHA-256 mismatch: got %s, expected %s"
                % (got_sha, want_sha)
            )
        check_macos_no_quarantine(staged_entry)
        os.replace(stage, final)
        print("chrome-for-testing %s (%s): installed and verified" % (version, plat))
        return final
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def self_test():
    plat = this_platform()
    if not plat:
        raise RuntimeError("unsupported platform")
    with open(VERSIONS, "rb") as f:
        doc = tomllib.load(f)
    for section in ("node", "browser_helper", "chrome_for_testing"):
        if section not in doc:
            raise RuntimeError("missing [%s] in %s" % (section, VERSIONS))
    with tempfile.TemporaryDirectory(prefix="ec-br-selftest-") as tmp:
        bad_zip = os.path.join(tmp, "bad.zip")
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../escape.txt", "nope")
        try:
            extract_zip(bad_zip, os.path.join(tmp, "out"))
        except ValueError:
            pass
        else:
            raise RuntimeError("extract_zip did not reject .. traversal")
    print("install-browser-runtime self-test: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-cache-dir", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--platform", default=None)
    args = parser.parse_args()

    if args.print_cache_dir:
        print(cache_dir())
        return 0
    if args.self_test:
        self_test()
        return 0

    plat = args.platform or this_platform()
    if not plat:
        sys.stderr.write("unsupported platform\n")
        return 1

    with open(VERSIONS, "rb") as f:
        doc = tomllib.load(f)

    cache = cache_dir()
    node_root = ensure_node(doc["node"], plat, cache)
    ensure_browser_helper(doc["browser_helper"], node_root, plat, cache)
    ensure_chrome(doc["chrome_for_testing"], plat, cache)
    return 0


if __name__ == "__main__":
    sys.exit(main())
