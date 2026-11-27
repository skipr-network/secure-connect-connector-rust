//! The one way this Connector replaces a state file it keeps next to the audit log: the whole
//! content goes to a temporary file that is then renamed over the old one, so a crash mid-write
//! never leaves a truncated file behind. Shared by the gateway-end queue (spec §B.18 point 1) and
//! the connection-event state (§B.22 point 5); each keeps its own state and its own lock.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

/// Serialises `value` and writes it atomically to `path`. `what` names the state in the error.
pub async fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T, what: &str) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).with_context(|| format!("failed to serialize the {what}"))?;
    write_atomically(path, &bytes).await
}

/// Writes `bytes` to a temporary file next to `path` and renames it over `path`, creating the
/// directory first when it is missing.
pub async fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let target = path.to_path_buf();
    let bytes = bytes.to_vec();
    // Synced before and after the rename, so a power loss (not only a crash) leaves the old or the
    // new file, never an empty one. Runs off the async workers: these are blocking calls.
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &target)
            .with_context(|| format!("failed to replace {}", target.display()))?;
        #[cfg(unix)]
        if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .with_context(|| format!("failed to sync {}", parent.display()))?;
        }
        Ok(())
    })
    .await
    .context("the state file write did not finish")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_the_whole_value_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");
        write_json(&path, &vec![1, 2, 3], "test state")
            .await
            .unwrap();
        write_json(&path, &vec![4], "test state").await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[4]");
        assert!(!path.with_extension("tmp").exists());
    }
}
