/// Task runner for yral-auth local deployments.
///
/// This crate contains ignored cargo tests that serve as deployment scripts.
/// Each test is a self-contained sequence of shell commands (build, push, SSH)
/// that you run from your local machine instead of relying on CI.
///
/// # Prerequisites
///
/// 1. **direnv + .env** — all secrets are loaded via environment variables.
///    Copy `.env.example` to `.env` (at the repo root), fill in the values,
///    and direnv will export them automatically (`.envrc` calls `dotenv_if_exists`).
///    The task_runner shares the same `.env` as yral-auth itself.
///
/// 2. **Docker** — must be running locally with buildx support.
///
/// 3. **GHCR login** — run `docker login ghcr.io -u <your-gh-username>` using
///    a PAT with `write:packages` scope.
///
/// 4. **SSH access to Hetzner hosts** — your SSH key must be authorized for
///    `yral-auth-manager@<host>` on each target server. Set `HETZNER_HOSTS`
///    in `.env` (space-separated IPs).
///
/// 5. **cross-compilation toolchain** — the build uses `cargo leptos` which
///    handles the musl cross-compile. Install with:
///    ```sh
///    cargo install cargo-leptos
///    rustup target add x86_64-unknown-linux-musl
///    ```
///
/// # Usage
///
/// ```sh
/// # Full deploy: build → docker build → save tarball → transfer + deploy
/// cargo test -p task_runner -- --ignored deploy --nocapture --test-threads=1
/// ```
pub mod shell;

#[cfg(test)]
mod tests;