/// Deployment tests for yral-auth — run from your local machine.
///
/// This is a local replacement for the CI workflow
/// (`.github/workflows/deploy-hetzner.yml`). All secrets come from `.env`
/// (loaded via direnv).
///
/// # Flow
///
/// 1. **Build** the musl binary + WASM via `cargo leptos build --release`
/// 2. **Build** the Docker image (using `deploy/Dockerfile`)
/// 3. **Save** the image to a tarball (no registry needed)
/// 4. **Transfer** the tarball + deploy files to each Hetzner host via rsync
/// 5. **Load** the image, restart docker compose with secrets
///
/// # Command
///
/// ```sh
/// cargo test -p task_runner -- --ignored deploy --nocapture --test-threads=1
/// ```
///
/// # Environment variables (set in .env at the repo root)
///
/// The task_runner shares the same `.env` as yral-auth. See `.env.example`
/// for the full list. The deployment-specific variables are:
/// | Variable | Required | Description |
/// |----------|----------|-------------|
/// | `HETZNER_HOSTS` | yes | Space-separated IPs of Hetzner servers |
/// | `GHCR_USERNAME` | yes | GitHub username for GHCR push |
/// | `GHCR_TOKEN` | yes | GitHub PAT with `write:packages` |
/// | `IMAGE_TAG` | no | Docker tag (default: `latest`) |
/// | `COOKIE_KEY` | yes | Cookie signing key |
/// | `GOOGLE_CLIENT_SECRET` | yes | Google OAuth client secret |
/// | `JWT_EC_PEM` | yes | JWT ES256 private key PEM |
/// | `CLIENT_JWT_ED_PEM` | yes | Client JWT Ed25519 private key PEM |
/// | `APPLE_AUTH_KEY_PEM` | no | Apple auth key PEM (if Apple OAuth enabled) |
/// | `WHATSAPP_API_KEY` | no | WhatsApp API key (if phone auth enabled) |
/// | `DRAGONFLY_REDIS_STORE_PASSWORD` | yes | Dragonfly/Redis password |
/// | `DRAGONFLY_REDIS_STORE_HOSTS` | yes | Dragonfly/Redis hosts |
/// | `DRAGONFLY_REDIS_STORE_CA_CERT` | yes | Redis TLS CA cert |
/// | `DRAGONFLY_REDIS_STORE_CLIENT_CERT` | yes | Redis TLS client cert |
/// | `DRAGONFLY_REDIS_STORE_CLIENT_KEY` | yes | Redis TLS client key |

use anyhow::{Context, Result};
use std::path::Path;

use crate::shell::{
    env_list, env_or, run, run_capture, run_with_env, workspace_root,
};

/// Docker registry + image name (used for tagging only — no registry push).
const IMAGE_NAME: &str = "yral-auth";

// ---------------------------------------------------------------------------
// Build steps
// ---------------------------------------------------------------------------

/// Build the musl binary + WASM via `cargo leptos`.
fn build_leptos(root: &Path) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Step 1: Building yral-auth (musl + WASM)...");
    println!("{}", "=".repeat(60));

    run_with_env(
        "cargo",
        &[
            "leptos",
            "build",
            "--release",
            "--lib-features",
            "release-lib",
            "--bin-features",
            "release-bin",
        ],
        root,
        &[
            ("LEPTOS_BIN_TARGET_TRIPLE", "x86_64-unknown-linux-musl"),
            ("LEPTOS_HASH_FILES", "true"),
            ("LEPTOS_TAILWIND_VERSION", "v4.0.15"),
        ],
    )?;

    // Verify the binary exists and is non-empty
    let binary = root.join("target/x86_64-unknown-linux-musl/release/yral-auth");
    let size = std::fs::metadata(&binary)
        .map(|m| m.len())
        .unwrap_or(0);
    println!("\n  ✓ binary: {} ({} bytes)", binary.display(), size);
    anyhow::ensure!(size > 0, "binary is empty — musl cross-compile may have failed");

    Ok(())
}

/// Build the Docker image using `deploy/Dockerfile`.
fn build_docker_image(root: &Path, tag: &str) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Step 2: Building Docker image...");
    println!("{}", "=".repeat(60));

    let full_tag = format!("{IMAGE_NAME}:{tag}");
    println!("  → building image {full_tag}");
    run(
        "docker",
        &[
            "build",
            "-f",
            "deploy/Dockerfile",
            "-t",
            &full_tag,
            ".",
        ],
        root,
    )?;
    println!("  ✓ image built: {full_tag}");
    Ok(())
}

/// Save the Docker image to a tarball for transfer to servers.
fn save_docker_image(root: &Path, tag: &str) -> Result<std::path::PathBuf> {
    println!("\n{}", "=".repeat(60));
    println!("Step 3: Saving Docker image to tarball...");
    println!("{}", "=".repeat(60));

    let full_tag = format!("{IMAGE_NAME}:{tag}");
    let tarball = root.join("target").join(format!("{IMAGE_NAME}-{tag}.tar"));
    println!("  → saving {full_tag} to {}", tarball.display());
    run("docker", &["save", "-o", tarball.to_str().unwrap(), &full_tag], root)?;
    let size = std::fs::metadata(&tarball).map(|m| m.len()).unwrap_or(0);
    println!("  ✓ tarball: {} ({} MB)", tarball.display(), size / 1_000_000);
    Ok(tarball)
}

// ---------------------------------------------------------------------------
// Deploy steps (SSH to Hetzner)
// ---------------------------------------------------------------------------

/// All secret env vars that need to be passed to the remote docker compose.
/// These are read from the local .env and forwarded via SSH.
fn secret_envs() -> Result<Vec<(&'static str, String)>> {
    let keys: &[&str] = &[
        "COOKIE_KEY",
        "GOOGLE_CLIENT_SECRET",
        "JWT_EC_PEM",
        "CLIENT_JWT_ED_PEM",
        "APPLE_AUTH_KEY_PEM",
        "WHATSAPP_API_KEY",
        "DRAGONFLY_REDIS_STORE_PASSWORD",
        "DRAGONFLY_REDIS_STORE_HOSTS",
        "DRAGONFLY_REDIS_STORE_CA_CERT",
        "DRAGONFLY_REDIS_STORE_CLIENT_CERT",
        "DRAGONFLY_REDIS_STORE_CLIENT_KEY",
    ];

    let mut envs = Vec::new();
    for key in keys {
        match std::env::var(key) {
            Ok(val) if !val.is_empty() => envs.push((*key, val)),
            Ok(_) => {
                println!("  ⚠ {key} is set but empty — skipping (may cause issues if needed)");
            }
            Err(_) => {
                println!("  ⚠ {key} not set — skipping (may cause issues if needed)");
            }
        }
    }
    Ok(envs)
}

/// Deploy to a single Hetzner host via SSH.
/// Transfers the Docker image tarball directly — no registry needed.
fn deploy_to_host(root: &Path, host: &str, tag: &str, tarball: &Path, ssh_key: &Path) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Deploying to {host}...");
    println!("{}", "=".repeat(60));

    let user = "yral-auth-manager";
    let remote = format!("{user}@{host}");
    let tarball_name = tarball.file_name().unwrap().to_str().unwrap();

    // SSH command prefix used by rsync -e and ssh directly
    let ssh_opts = format!(
        "ssh -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        ssh_key.display()
    );

    // Step 1: Sync deploy/ files to the server
    println!("  → syncing deploy/ files...");
    run(
        "rsync",
        &[
            "-avz",
            "--delete",
            "-e",
            &ssh_opts,
            "./deploy/",
            &format!("{remote}:/home/{user}/"),
        ],
        root,
    )?;

    // Step 2: Transfer the Docker image tarball
    println!("  → transferring image tarball ({tarball_name})...");
    run(
        "rsync",
        &[
            "-avz",
            "--progress",
            "-e",
            &ssh_opts,
            tarball.to_str().unwrap(),
            &format!("{remote}:/home/{user}/{tarball_name}"),
        ],
        root,
    )?;

    // Step 3: Load the image on the server
    println!("  → loading image on server...");
    let load_cmd = format!("docker load -i /home/{user}/{tarball_name}");
    run("ssh", &["-i", ssh_key.to_str().unwrap(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", &remote, &load_cmd], root)?;

    // Step 4: Stop existing containers
    println!("  → stopping existing containers...");
    let stop_cmd = format!("cd /home/{user} && docker compose down --remove-orphans || true");
    run("ssh", &["-i", ssh_key.to_str().unwrap(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", &remote, &stop_cmd], root)?;

    // Step 5: Start with new image + secrets
    println!("  → starting services...");

    // Build the env var prefix for docker compose up
    let secrets = secret_envs()?;
    let mut env_prefix = format!("APP_IMAGE={IMAGE_NAME} IMAGE_TAG={tag}");
    for (key, val) in &secrets {
        // Escape single quotes in values for shell safety
        let escaped = val.replace('\'', "'\\''");
        env_prefix.push_str(&format!(" {key}='{escaped}'"));
    }

    let up_cmd = format!("cd /home/{user} && {env_prefix} docker compose up -d");
    run("ssh", &["-i", ssh_key.to_str().unwrap(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", &remote, &up_cmd], root)?;

    // Step 6: Wait and verify
    println!("  → waiting for services to start...");
    std::thread::sleep(std::time::Duration::from_secs(10));

    println!("  → checking status...");
    let status_cmd = format!(
        "cd /home/{user} && docker compose ps && echo '---' && docker compose logs --tail=20 yral-auth 2>/dev/null || true"
    );
    let output = run_capture("ssh", &["-i", ssh_key.to_str().unwrap(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", &remote, &status_cmd], root)?;
    println!("{output}");

    // Step 7: Health check
    println!("  → health check...");
    let health_cmd = format!("curl -sf http://localhost/healthz || echo 'Health check failed'");
    let health = run_capture("ssh", &["-i", ssh_key.to_str().unwrap(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", &remote, &health_cmd], root)?;
    println!("  health: {health}");

    // Step 8: Clean up tarball on server
    println!("  → cleaning up tarball on server...");
    let cleanup_cmd = format!("rm -f /home/{user}/{tarball_name}");
    run("ssh", &["-i", ssh_key.to_str().unwrap(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", &remote, &cleanup_cmd], root)?;

    println!("  ✓ {host} deployed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full deploy: build → docker build → save tarball → transfer + deploy to all hosts.
///
/// ```sh
/// cargo test -p task_runner -- --ignored deploy --nocapture --test-threads=1
/// ```
#[tokio::test]
#[ignore = "deploys yral-auth to production Hetzner hosts — run explicitly"]
async fn deploy() -> Result<()> {
    let root = workspace_root();
    let tag = env_or("IMAGE_TAG", "latest");

    println!("yral-auth deployment");
    println!("  workspace: {}", root.display());
    println!("  image tag: {tag}");
    println!("  hosts:     {:?}", env_list("HETZNER_HOSTS")?);

    // 0. Write SSH private key to a temp file
    let ssh_key_content = require_env("SSH_PRIVATE_KEY")?;
    let ssh_key = root.join("target/.ssh-key");
    std::fs::write(&ssh_key, &ssh_key_content)?;
    std::fs::set_permissions(&ssh_key, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    println!("  ✓ SSH key written to {}", ssh_key.display());

    // 1. Build
    build_leptos(&root)?;

    // 2. Docker build
    build_docker_image(&root, &tag)?;

    // 3. Save image to tarball
    let tarball = save_docker_image(&root, &tag)?;

    // 4. Deploy to each host (serial — one at a time)
    let hosts = env_list("HETZNER_HOSTS")?;
    for host in &hosts {
        deploy_to_host(&root, host, &tag, &tarball, &ssh_key)?;
    }

    // 5. Clean up local tarball + SSH key
    println!("\n  → cleaning up local files...");
    std::fs::remove_file(&tarball).ok();
    std::fs::remove_file(&ssh_key).ok();

    println!("\n{}", "=".repeat(60));
    println!("✓ Deployment complete — {} host(s)", hosts.len());
    println!("{}", "=".repeat(60));
    Ok(())
}