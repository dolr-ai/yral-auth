/// Deployment tests for yral-auth — run from your local machine.
///
/// These tests replace the CI workflow (`.github/workflows/deploy-hetzner.yml`)
/// for manual deploys. All secrets come from `.env` (loaded via direnv).
///
/// # Flow
///
/// 1. **Build** the musl binary + WASM via `cargo leptos build --release`
/// 2. **Build** the Docker image (using `deploy/Dockerfile`)
/// 3. **Push** the image to `ghcr.io/dolr-ai/yral-auth:<tag>`
/// 4. **SSH** to each Hetzner host, sync `deploy/` files, pull image, restart
///
/// # Commands
///
/// ```sh
/// # Full deploy (build + push + SSH deploy)
/// cargo test -p task_runner -- --ignored deploy --nocapture
///
/// # Build only (no push, no deploy) — useful for testing the build locally
/// cargo test -p task_runner -- --ignored build_only --nocapture
///
/// # Deploy only (skip build — use an already-pushed image tag)
/// # Set IMAGE_TAG in .env to the tag you want to deploy.
/// cargo test -p task_runner -- --ignored deploy_only --nocapture
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
    env_list, env_or, require_env, run, run_capture, run_with_env, workspace_root,
};

/// Docker registry + image name.
const DOCKER_REGISTRY: &str = "ghcr.io";
const IMAGE_NAME: &str = "dolr-ai/yral-auth";

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
    println!("  binary: {} ({} bytes)", binary.display(), size);
    anyhow::ensure!(size > 0, "binary is empty — musl cross-compile may have failed");

    Ok(())
}

/// Build the Docker image using `deploy/Dockerfile`.
fn build_docker_image(root: &Path, tag: &str) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Step 2: Building Docker image...");
    println!("{}", "=".repeat(60));

    let full_tag = format!("{DOCKER_REGISTRY}/{IMAGE_NAME}:{tag}");
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
    println!("  image: {full_tag}");
    Ok(())
}

/// Push the Docker image to GHCR.
fn push_docker_image(root: &Path, tag: &str) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Step 3: Pushing Docker image to GHCR...");
    println!("{}", "=".repeat(60));

    let username = require_env("GHCR_USERNAME")?;
    let token = require_env("GHCR_TOKEN")?;

    // Login (pipe token via stdin for --password-stdin)
    println!("  Logging in to GHCR...");
    let login_status = std::process::Command::new("docker")
        .args(["login", DOCKER_REGISTRY, "-u", &username, "--password-stdin"])
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("failed to spawn docker login")?;
    use std::io::Write;
    let mut child = login_status;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(token.as_bytes()).context("failed to write token to stdin")?;
    }
    let output = child.wait_with_output().context("failed to wait for docker login")?;
    anyhow::ensure!(output.status.success(), "docker login failed");

    // Push
    let full_tag = format!("{DOCKER_REGISTRY}/{IMAGE_NAME}:{tag}");
    run("docker", &["push", &full_tag], root)?;
    println!("  pushed: {full_tag}");
    Ok(())
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
fn deploy_to_host(root: &Path, host: &str, tag: &str) -> Result<()> {
    println!("\n{}", "=".repeat(60));
    println!("Deploying to {host}...");
    println!("{}", "=".repeat(60));

    let user = "yral-auth-manager";
    let remote = format!("{user}@{host}");
    let full_tag = format!("{DOCKER_REGISTRY}/{IMAGE_NAME}:{tag}");

    // Step 1: Sync deploy/ files to the server
    println!("  Syncing deploy/ files...");
    run(
        "rsync",
        &[
            "-avz",
            "--delete",
            "./deploy/",
            &format!("{remote}:/home/{user}/"),
        ],
        root,
    )?;

    // Step 2: Pull the image on the server
    println!("  Pulling image {full_tag}...");
    let pull_cmd = format!(
        "cd /home/{user} && \
         echo '{}' | docker login {DOCKER_REGISTRY} -u {} --password-stdin && \
         APP_IMAGE={DOCKER_REGISTRY}/{IMAGE_NAME} IMAGE_TAG={tag} docker compose pull",
        require_env("GHCR_TOKEN")?,
        require_env("GHCR_USERNAME")?,
    );
    run("ssh", &["-o", "ConnectTimeout=10", &remote, &pull_cmd], root)?;

    // Step 3: Stop existing containers
    println!("  Stopping existing containers...");
    let stop_cmd = format!("cd /home/{user} && docker compose down --remove-orphans || true");
    run("ssh", &["-o", "ConnectTimeout=10", &remote, &stop_cmd], root)?;

    // Step 4: Start with new image + secrets
    println!("  Starting services with new image...");

    // Build the env var prefix for docker compose up
    let secrets = secret_envs()?;
    let mut env_prefix = format!(
        "APP_IMAGE={DOCKER_REGISTRY}/{IMAGE_NAME} IMAGE_TAG={tag}"
    );
    for (key, val) in &secrets {
        // Escape single quotes in values for shell safety
        let escaped = val.replace('\'', "'\\''");
        env_prefix.push_str(&format!(" {key}='{escaped}'"));
    }

    let up_cmd = format!(
        "cd /home/{user} && {env_prefix} docker compose up -d"
    );
    run("ssh", &["-o", "ConnectTimeout=10", &remote, &up_cmd], root)?;

    // Step 5: Wait and verify
    println!("  Waiting for services to start...");
    std::thread::sleep(std::time::Duration::from_secs(10));

    println!("  Checking status...");
    let status_cmd = format!("cd /home/{user} && docker compose ps && echo '---' && docker compose logs --tail=20 yral-auth 2>/dev/null || true");
    let output = run_capture("ssh", &["-o", "ConnectTimeout=10", &remote, &status_cmd], root)?;
    println!("{output}");

    // Step 6: Health check
    println!("  Health check...");
    let health_cmd = format!("curl -sf http://localhost/healthz || echo 'Health check failed'");
    let health = run_capture("ssh", &["-o", "ConnectTimeout=10", &remote, &health_cmd], root)?;
    println!("  health: {health}");

    println!("  ✓ {host} deployed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full deploy: build → docker build → push → SSH deploy to all hosts.
///
/// ```sh
/// cargo test -p task_runner -- --ignored deploy --nocapture
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

    // 1. Build
    build_leptos(&root)?;

    // 2. Docker build
    build_docker_image(&root, &tag)?;

    // 3. Push
    push_docker_image(&root, &tag)?;

    // 4. Deploy to each host (serial — one at a time)
    let hosts = env_list("HETZNER_HOSTS")?;
    for host in &hosts {
        deploy_to_host(&root, host, &tag)?;
    }

    println!("\n{}", "=".repeat(60));
    println!("✓ Deployment complete — {} host(s)", hosts.len());
    println!("{}", "=".repeat(60));
    Ok(())
}

/// Build only — no push, no deploy. Useful for testing the build locally.
///
/// ```sh
/// cargo test -p task_runner -- --ignored build_only --nocapture
/// ```
#[tokio::test]
#[ignore = "builds yral-auth locally — run explicitly"]
async fn build_only() -> Result<()> {
    let root = workspace_root();
    let tag = env_or("IMAGE_TAG", "latest");

    println!("yral-auth build only");
    println!("  workspace: {}", root.display());
    println!("  image tag: {tag}");

    build_leptos(&root)?;
    build_docker_image(&root, &tag)?;

    println!("\n✓ Build complete (not pushed, not deployed)");
    Ok(())
}

/// Deploy only — skip build, use an already-pushed image tag.
///
/// Set `IMAGE_TAG` in `.env` to the tag you want to deploy.
///
/// ```sh
/// cargo test -p task_runner -- --ignored deploy_only --nocapture
/// ```
#[tokio::test]
#[ignore = "deploys an existing yral-auth image to Hetzner — run explicitly"]
async fn deploy_only() -> Result<()> {
    let root = workspace_root();
    let tag = env_or("IMAGE_TAG", "latest");

    println!("yral-auth deploy only (no build)");
    println!("  workspace: {}", root.display());
    println!("  image tag: {tag}");
    println!("  hosts:     {:?}", env_list("HETZNER_HOSTS")?);

    let hosts = env_list("HETZNER_HOSTS")?;
    for host in &hosts {
        deploy_to_host(&root, host, &tag)?;
    }

    println!("\n✓ Deploy complete — {} host(s)", hosts.len());
    Ok(())
}