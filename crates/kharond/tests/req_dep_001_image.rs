//! REQ-DEP-001 (issue #24): distroless/static image, non-root,
//! read-only rootfs, under 30 MB.
//!
//! Runs against a built image (`KHARON_IMAGE`, e.g. `kharon:e2e` from
//! the repo `Dockerfile`); ignored by default. `image.yml` builds the
//! image, runs these, and runs the AC's Trivy half (0 high/critical)
//! as its own step.

mod docker_support;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use docker_support::{docker, docker_raw, wait_for_log};

const MAX_IMAGE_BYTES: u64 = 30 * 1000 * 1000;
const RUNTIME_USER: &str = "10001:10001";

fn image() -> String {
    std::env::var("KHARON_IMAGE").expect("KHARON_IMAGE must name the built image (see image.yml)")
}

#[test]
#[ignore = "needs a built kharon image (image.yml)"]
fn req_dep_001_image_is_under_30_mb() {
    let size: u64 = docker(&["image", "inspect", "--format", "{{.Size}}", &image()])
        .trim()
        .parse()
        .unwrap();
    eprintln!("image size: {size} bytes");
    assert!(size < MAX_IMAGE_BYTES, "image is {size} bytes, limit 30 MB");
}

#[test]
#[ignore = "needs a built kharon image (image.yml)"]
fn req_dep_001_image_runs_as_non_root() {
    let user = docker(&["image", "inspect", "--format", "{{.Config.User}}", &image()]);
    assert_eq!(user.trim(), RUNTIME_USER);
}

#[test]
#[ignore = "needs a built kharon image (image.yml)"]
fn req_dep_001_image_is_static_with_no_shell() {
    // distroless/static: no /bin/sh (nor a libc to load one with).
    let out = docker_raw(
        &[
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            &image(),
            "-c",
            "true",
        ],
        None,
    );
    assert!(!out.status.success(), "the image has a shell");
}

/// `docker run --read-only` with SPEC §9's runtime flags: kharond
/// boots locked, serves, answers the owner CLI from inside the
/// container, and shuts down cleanly on SIGTERM. The only writable
/// path is the fresh `/data` volume.
#[test]
#[ignore = "needs a built kharon image (image.yml)"]
fn req_dep_001_read_only_rootfs_serves() {
    let dir = tempfile::tempdir().unwrap();
    // Export mode: the password-protected fixture export (#12) lets
    // kharond boot without a Vaultwarden.
    let export = dir.path().join("export.json");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        ),
        &export,
    )
    .unwrap();
    let config = dir.path().join("kharon.toml");
    std::fs::write(
        &config,
        r#"mode = "export"

[export]
file = "/etc/kharon/export.json"

[agents.assistant]
token_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
cdp = { endpoint = "ws://127.0.0.1:9222/devtools/browser" }

[audit]
checkpoint_local_only = true

[api]
listen = "127.0.0.1:8787"
"#,
    )
    .unwrap();
    // Readable by the container's uid; nothing here is secret.
    for p in [&export, &config] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let name = format!("kharon-req-dep-001-{}", std::process::id());
    let volume = format!("{name}-data");
    let config_mount = format!("{}:/etc/kharon.toml:ro", config.display());
    let export_mount = format!("{}:/etc/kharon/export.json:ro", export.display());
    let data_mount = format!("{volume}:/data");
    let run = docker_raw(
        &[
            "run",
            "-d",
            "--name",
            &name,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "IPC_LOCK",
            "--ulimit",
            "memlock=-1:-1",
            "--ulimit",
            "core=0:0",
            "--security-opt",
            "no-new-privileges:true",
            "-v",
            &data_mount,
            "-v",
            &config_mount,
            "-v",
            &export_mount,
            &image(),
        ],
        None,
    );
    let cleanup = || {
        let _ = docker_raw(&["rm", "-f", &name], None);
        let _ = docker_raw(&["volume", "rm", "-f", &volume], None);
    };
    if !run.status.success() {
        cleanup();
        panic!("docker run: {}", String::from_utf8_lossy(&run.stderr));
    }

    let result = std::panic::catch_unwind(|| {
        // Default require_mlock = true: the memlock ulimit carries it.
        let logs = wait_for_log(
            &name,
            "agent API listening on 127.0.0.1:8787 (locked)",
            Duration::from_secs(30),
        );
        assert!(!logs.contains("require_mlock = false"), "{logs}");
        let status = docker(&["exec", &name, "kharon", "status"]);
        assert_eq!(status.trim(), "locked");
        let ro = docker(&[
            "inspect",
            "--format",
            "{{.HostConfig.ReadonlyRootfs}}",
            &name,
        ]);
        assert_eq!(ro.trim(), "true");
        let pid_user = docker(&["top", &name, "-eo", "pid,uid,comm"]);
        assert!(
            pid_user
                .lines()
                .skip(1)
                .all(|l| l.split_whitespace().nth(1) == Some("10001")),
            "a process in the container is not uid 10001:\n{pid_user}"
        );
        docker(&["stop", "-t", "10", &name]);
        let code = docker(&["inspect", "--format", "{{.State.ExitCode}}", &name]);
        let logs = wait_for_log(&name, "kharond: shut down", Duration::from_secs(5));
        assert_eq!(code.trim(), "0", "{logs}");
    });
    cleanup();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
