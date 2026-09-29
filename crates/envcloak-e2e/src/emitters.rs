//! The story's command and its serializers (gate 8 through the whole of
//! `envcloak run`): `tests/fixtures/emitters/emit.py` puts each value
//! through Python's serializers and runs the other runtimes' emitters,
//! which this module finds or builds: Node (`emit.js`), Go (`emit.go`,
//! built here), .NET (`Emit.cs`, built here), PHP (`emit.php`) and
//! serde_json (`ec-emit-serde`, a program of this crate).
//!
//! A runtime that is not installed is left out and named in
//! [`Emitters::missing`]; `ENVCLOAK_TEST_REQUIRE_EMITTERS` (a comma list
//! of tags: `python`, `node`, `go`, `dotnet`, `php`, `serde`) makes a
//! missing one fail the test instead. CI requires them all on both
//! systems.
//!
//! [`Emitters::oracle`] runs the emitters outside EnvCloak with the
//! fixture values and returns what each serializer made of each: the test
//! looks for those bytes, as they are, in everything the story printed
//! (the F-9 lesson: a serializer's output is taken from the serializer,
//! never typed).

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_testkit::TestHome;
use sha2::{Digest, Sha256};

use crate::{find_on_path, finish_within, python3, quoted};

/// The variables the story's manifest binds by default, as `emit` is told
/// to serialize them.
pub const NAMES: [&str; 4] = [
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "STRIPE_SECRET_KEY",
];

/// Where the emitters' sources are.
fn sources() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emitters")
}

/// Lower-case hex SHA-256 of `v`.
pub fn sha256_hex(v: &[u8]) -> String {
    Sha256::digest(v).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The emitters found or built.
#[derive(Debug, Clone)]
pub struct Emitters {
    python: PathBuf,
    /// Each runtime's tag and command (the variable names are appended).
    runtimes: Vec<(String, Vec<String>)>,
    /// Tags of the runtimes that are not installed here.
    pub missing: Vec<&'static str>,
}

impl Emitters {
    /// Finds the runtimes and builds the Go and .NET emitters under
    /// `build_dir` (reused while their source and toolchain are the same).
    /// `serde` is the `ec-emit-serde` program.
    ///
    /// # Panics
    /// When a runtime `ENVCLOAK_TEST_REQUIRE_EMITTERS` names is missing,
    /// or a build fails.
    pub fn prepare(build_dir: &Path, serde: &Path) -> Emitters {
        let src = sources();
        let path_of = |p: &Path| p.to_str().unwrap_or("").to_owned();
        let mut runtimes = Vec::new();
        let mut missing = Vec::new();
        match find_on_path("node") {
            Some(node) => runtimes.push((
                "node".to_owned(),
                vec![path_of(&node), path_of(&src.join("emit.js"))],
            )),
            None => missing.push("node"),
        }
        match find_on_path("go").map(|go| build_go(&go, build_dir)) {
            Some(bin) => runtimes.push(("go".to_owned(), vec![path_of(&bin)])),
            None => missing.push("go"),
        }
        match find_on_path("dotnet") {
            Some(dotnet) => {
                let dll = build_dotnet(&dotnet, build_dir);
                runtimes.push(("dotnet".to_owned(), vec![path_of(&dotnet), path_of(&dll)]));
            }
            None => missing.push("dotnet"),
        }
        match find_on_path("php") {
            Some(php) => runtimes.push((
                "php".to_owned(),
                vec![path_of(&php), path_of(&src.join("emit.php"))],
            )),
            None => missing.push("php"),
        }
        runtimes.push(("serde".to_owned(), vec![path_of(serde)]));
        let required = std::env::var("ENVCLOAK_TEST_REQUIRE_EMITTERS").unwrap_or_default();
        for tag in required.split(',').filter(|t| !t.is_empty()) {
            assert!(
                !missing.contains(&tag),
                "the {tag} serializer is required (ENVCLOAK_TEST_REQUIRE_EMITTERS) but not installed"
            );
            assert!(
                ["python", "node", "go", "dotnet", "php", "serde"].contains(&tag),
                "unknown serializer {tag}"
            );
        }
        Emitters {
            python: python3(),
            runtimes,
            missing,
        }
    }

    /// The serializers `emit` reports, in its order: `python` first.
    pub fn tags(&self) -> Vec<String> {
        let mut t = vec!["python".to_owned()];
        t.extend(self.runtimes.iter().map(|(tag, _)| tag.clone()));
        t
    }

    /// Writes `emit`'s configuration to `path`: the variables, the ones
    /// the full mode splits at every byte, and the runtimes.
    ///
    /// # Panics
    /// When it cannot be written.
    pub fn write_config(&self, path: &Path, split: &[&str]) {
        let cfg = serde_json::json!({
            "names": NAMES,
            "split": split,
            "pause_ms": 45,
            "runtimes": self.runtimes,
        });
        std::fs::write(path, cfg.to_string())
            .unwrap_or_else(|e| panic!("write the emitter configuration: {e}"));
    }

    /// The `emit` script's text: `emit.py` with the configuration at
    /// `config`, passing on its own arguments (`--quick`,
    /// `--digests-only`). Paths are absolute: `envcloak run` gives the
    /// command the agent's environment, whose `PATH` has system
    /// directories only.
    pub fn script(&self, config: &Path) -> String {
        format!(
            "#!/bin/sh\n# The fixture story's command: each value through every serializer, then \
             the digests (tests/fixtures/emitters/emit.py).\nexec {} {} --config {} \"$@\"\n",
            quoted(self.python.to_str().unwrap_or("")),
            quoted(sources().join("emit.py").to_str().unwrap_or("")),
            quoted(config.to_str().unwrap_or(""))
        )
    }

    /// What each serializer makes of `values` (`(name, value)` for every
    /// one of [`NAMES`]): `emit.py --oracle` run outside EnvCloak, in a
    /// home of its own with nothing else in its environment. Each result
    /// is labeled `<NAME>/<serializer>`.
    ///
    /// # Panics
    /// When it fails.
    pub fn oracle(&self, config: &Path, values: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        let home = TestHome::new();
        let mut cmd = Command::new(&self.python);
        home.apply(&mut cmd);
        for (name, value) in values {
            cmd.env(name, OsStr::from_bytes(value));
        }
        cmd.arg(sources().join("emit.py"))
            .arg("--config")
            .arg(config)
            .arg("--oracle")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish_within(cmd, Duration::from_secs(300));
        // Its standard error holds no value (emit.py's errors never do).
        assert!(
            out.status.success(),
            "the emitters failed outside EnvCloak: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut parts: Vec<&[u8]> = out.stdout.split(|b| *b == 0).collect();
        if parts.last().is_some_and(|p| p.is_empty()) {
            parts.pop();
        }
        assert!(parts.len() % 2 == 0, "the emitters' records are cut short");
        parts
            .chunks(2)
            .map(|p| (String::from_utf8_lossy(p[0]).into_owned(), p[1].to_vec()))
            .collect()
    }
}

/// A short hash of `parts`, to key a build directory.
fn key(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    sha256_hex(&h.finalize())[..16].to_owned()
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Builds `emit.go` with `go` into `build_dir`, once per source.
fn build_go(go: &Path, build_dir: &Path) -> PathBuf {
    let src = sources().join("emit.go");
    let dir = build_dir.join(format!("go-{}", key(&[&read(&src)])));
    let bin = dir.join("emit-go");
    if bin.is_file() {
        return bin;
    }
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    let home = TestHome::new();
    let mut cmd = Command::new(go);
    home.apply(&mut cmd)
        .env("GOCACHE", dir.join("cache"))
        .env("GOPATH", dir.join("path"))
        .env("GOTOOLCHAIN", "local")
        .env("GO111MODULE", "off")
        .env("CGO_ENABLED", "0")
        .arg("build")
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = finish_within(cmd, Duration::from_secs(300));
    assert!(
        out.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

/// Builds `Emit.cs` with `dotnet` into `build_dir`, once per source and
/// SDK, and returns the program's DLL (run as `dotnet Emit.dll`). No build
/// server is left running.
fn build_dotnet(dotnet: &Path, build_dir: &Path) -> PathBuf {
    let src = sources().join("Emit.cs");
    let home = TestHome::new();
    let dotnet_dir = dotnet.parent().map(Path::to_path_buf).unwrap_or_default();
    let env = |cmd: &mut Command| {
        home.apply(cmd);
        let path = format!("{}:{}", dotnet_dir.display(), envcloak_testkit::TEST_PATH);
        cmd.env("PATH", path)
            .env("DOTNET_CLI_HOME", home.home())
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_NOLOGO", "1")
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .env("DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER", "1")
            .env("MSBUILDDISABLENODEREUSE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    };
    let mut version = Command::new(dotnet);
    env(&mut version);
    version.arg("--version");
    let v = finish_within(version, Duration::from_secs(120));
    assert!(v.status.success(), "dotnet --version failed");
    let sdk = String::from_utf8_lossy(&v.stdout).trim().to_owned();
    let major = sdk.split('.').next().unwrap_or("8").to_owned();
    let dir = build_dir.join(format!("dotnet-{}", key(&[&read(&src), sdk.as_bytes()])));
    let dll = dir.join("out/Emit.dll");
    if dll.is_file() {
        return dll;
    }
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    let project = dir.join("Emit.csproj");
    std::fs::write(
        &project,
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
             <OutputType>Exe</OutputType>\n    <TargetFramework>net{major}.0</TargetFramework>\n    \
             <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    \
             <InvariantGlobalization>true</InvariantGlobalization>\n    \
             <UseAppHost>false</UseAppHost>\n    \
             <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n  </PropertyGroup>\n  \
             <ItemGroup>\n    <Compile Include=\"{}\" />\n  </ItemGroup>\n</Project>\n",
            src.display()
        ),
    )
    .unwrap_or_else(|e| panic!("write the .NET project: {e}"));
    let mut build = Command::new(dotnet);
    env(&mut build);
    build
        .arg("build")
        .arg(&project)
        .args(["-c", "Release", "-nologo", "-v:q", "-nodeReuse:false"])
        .arg("-p:UseSharedCompilation=false")
        .arg("-o")
        .arg(dir.join("out"))
        .env("NUGET_PACKAGES", dir.join("nuget"));
    let out = finish_within(build, Duration::from_secs(600));
    assert!(
        out.status.success() && dll.is_file(),
        "dotnet build failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    dll
}
