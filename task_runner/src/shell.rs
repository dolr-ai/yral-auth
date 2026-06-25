use anyhow::{Context, Result};
use std::process::Command;

/// Run a command, inherit stdout/stderr, and return an error on non-zero exit.
pub fn run(cmd: &str, args: &[&str], cwd: &std::path::Path) -> Result<()> {
    println!("  $ {} {}", cmd, args.join(" "));
    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to execute `{cmd}`"))?;
    anyhow::ensure!(status.success(), "`{cmd} {}` exited with {status}", args.join(" "));
    Ok(())
}

/// Run a command and capture its stdout (trimmed). Errors on non-zero exit.
pub fn run_capture(cmd: &str, args: &[&str], cwd: &std::path::Path) -> Result<String> {
    println!("  $ {} {}", cmd, args.join(" "));
    let output = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to execute `{cmd}`"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("`{cmd} {}` exited with {}\nstderr: {stderr}", args.join(" "), output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a command with environment variables, inherit stdout/stderr.
pub fn run_with_env(
    cmd: &str,
    args: &[&str],
    cwd: &std::path::Path,
    envs: &[(&str, &str)],
) -> Result<()> {
    print!("  $ ");
    for (k, v) in envs {
        // Truncate long values (PEMs, secrets) for log readability
        let display_val = if v.len() > 40 {
            format!("{}…", &v[..37])
        } else {
            v.to_string()
        };
        print!("{k}={display_val} ");
    }
    println!("{} {}", cmd, args.join(" "));

    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .envs(envs.iter().copied())
        .status()
        .with_context(|| format!("failed to execute `{cmd}`"))?;
    anyhow::ensure!(status.success(), "`{cmd} {}` exited with {status}", args.join(" "));
    Ok(())
}

/// Returns the workspace root (parent of this crate's Cargo.toml).
pub fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Get a required environment variable, with a helpful error message if missing.
pub fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| {
        format!(
            "`{key}` is not set. Add it to .env (see .env.example for the full list)."
        )
    })
}

/// Get an environment variable with a default value.
pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse a space-separated list from an env var (e.g. HETZNER_HOSTS).
pub fn env_list(key: &str) -> Result<Vec<String>> {
    let val = require_env(key)?;
    Ok(val.split_whitespace().map(|s| s.to_string()).collect())
}