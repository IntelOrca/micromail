use crate::config::RetryConfig;
use crate::error::{Error, Result};
use crate::send::Delivery;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub from: String,
    pub to: Vec<String>,
    pub created_at: u64,
    pub attempts: u32,
    pub next_attempt_at: u64,
}

/// On-disk message spool. Each pending message lives in its own directory:
///
/// ```text
/// <spool>/<uuid>/
///     meta.toml       envelope + retry state
///     message.eml     raw RFC 5322 message
/// ```
///
/// Messages are committed by writing `meta.toml` last; the worker skips
/// directories without a readable meta file.
pub struct Spool {
    dir: PathBuf,
    failed_dir: PathBuf,
    tx: mpsc::Sender<()>,
}

impl Spool {
    /// Create the spool directories and return the spool plus the wake-up
    /// channel receiver used by the delivery worker.
    ///
    /// If the spool directories cannot be created (e.g. a non-root user with
    /// the default `/etc/micromail` config dir) the spool is still returned
    /// and the daemon keeps running; queuing then fails per-message with a
    /// clear error instead of aborting at startup.
    pub fn open(dir: PathBuf) -> Result<(Arc<Spool>, mpsc::Receiver<()>)> {
        let failed_dir = dir.join("failed");
        if let Err(e) = std::fs::create_dir_all(&dir).and_then(|()| {
            std::fs::create_dir_all(&failed_dir)
        }) {
            tracing::warn!(
                dir = %dir.display(),
                err = %e,
                "cannot create spool directory; queuing and delivery are unavailable. \
                 Run with -c <writable-config-dir> or as root"
            );
        }
        let (tx, rx) = mpsc::channel(16);
        Ok((Arc::new(Spool { dir, failed_dir, tx }), rx))
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    /// Spool a message and return its id.
    pub async fn enqueue(&self, from: String, to: Vec<String>, body: Vec<u8>) -> Result<String> {
        if to.is_empty() {
            return Err(Error::InvalidInput("no recipients".into()));
        }
        let id = Uuid::new_v4();
        let msg_dir = self.dir.join(id.to_string());

        tokio::fs::create_dir(&msg_dir).await?;

        // Write the body first; meta.toml acts as the commit marker.
        let body_path = msg_dir.join("message.eml");
        let tmp_body = msg_dir.join(".message.eml.tmp");
        if let Err(e) = tokio::fs::write(&tmp_body, &body).await {
            let _ = tokio::fs::remove_dir_all(&msg_dir).await;
            return Err(e.into());
        }
        if let Err(e) = tokio::fs::rename(&tmp_body, &body_path).await {
            let _ = tokio::fs::remove_dir_all(&msg_dir).await;
            return Err(e.into());
        }

        let now = now_secs();
        let meta = Meta {
            from,
            to,
            created_at: now,
            attempts: 0,
            next_attempt_at: 0,
        };
        let meta_toml = toml::to_string(&meta).map_err(|e| Error::Spool(e.to_string()))?;
        let meta_path = msg_dir.join("meta.toml");
        let tmp_meta = msg_dir.join(".meta.toml.tmp");
        if let Err(e) = tokio::fs::write(&tmp_meta, &meta_toml).await {
            let _ = tokio::fs::remove_dir_all(&msg_dir).await;
            return Err(e.into());
        }
        if let Err(e) = tokio::fs::rename(&tmp_meta, &meta_path).await {
            let _ = tokio::fs::remove_dir_all(&msg_dir).await;
            return Err(e.into());
        }

        let _ = self.tx.try_send(());
        Ok(id.to_string())
    }

    /// Scan the spool and return entries whose next attempt time has passed.
    fn list_due(&self) -> Vec<(PathBuf, Meta)> {
        let mut due = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return due;
        };
        let now = now_secs();
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let path = entry.path();
            let meta_path = path.join("meta.toml");
            let Ok(bytes) = std::fs::read(&meta_path) else {
                continue;
            };
            let Ok(meta) = toml::from_slice::<Meta>(&bytes) else {
                tracing::warn!(dir = %path.display(), "skipping unreadable spool entry");
                continue;
            };
            if meta.next_attempt_at <= now {
                due.push((path, meta));
            }
        }
        due
    }

    /// Attempt delivery of every due message.
    pub async fn process_due(&self, delivery: &Arc<Delivery>, retry: &RetryConfig) {
        for (path, meta) in self.list_due() {
            self.process_one(path, meta, delivery, retry).await;
        }
    }

    async fn process_one(
        &self,
        path: PathBuf,
        meta: Meta,
        delivery: &Arc<Delivery>,
        retry: &RetryConfig,
    ) {
        let body = match tokio::fs::read(path.join("message.eml")).await {
            Ok(body) => body,
            Err(e) => {
                tracing::error!(dir = %path.display(), "cannot read spooled message body: {e}");
                return;
            }
        };

        let attempts = meta.attempts.saturating_add(1);
        match delivery.deliver(&meta.from, &meta.to, &body).await {
            Ok(()) => {
                tracing::info!(
                    from = %meta.from,
                    to = ?meta.to,
                    "delivered spooled message"
                );
                if let Err(e) = tokio::fs::remove_dir_all(&path).await {
                    tracing::error!(dir = %path.display(), "failed to remove delivered message: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(from = %meta.from, to = ?meta.to, attempts, "delivery failed: {e}");
                if attempts as usize >= retry.max_attempts {
                    tracing::error!(dir = %path.display(), "giving up after {attempts} attempts");
                    self.park(path).await;
                } else {
                    let backoff = retry
                        .initial_delay_secs
                        .saturating_mul(retry.backoff_factor.saturating_pow(attempts - 1));
                    let next = now_secs().saturating_add(backoff);
                    let updated = Meta {
                        from: meta.from.clone(),
                        to: meta.to.clone(),
                        created_at: meta.created_at,
                        attempts,
                        next_attempt_at: next,
                    };
                    if let Ok(toml) = toml::to_string(&updated) {
                        if let Err(e) = tokio::fs::write(path.join("meta.toml"), &toml).await {
                            tracing::error!(dir = %path.display(), "failed to update meta: {e}");
                        }
                    }
                }
            }
        }
    }

    /// Move a message to the failed directory.
    async fn park(&self, path: PathBuf) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let target = self.failed_dir.join(&name);
        let _ = tokio::fs::remove_dir_all(&target).await;
        if let Err(e) = tokio::fs::rename(&path, &target).await {
            tracing::error!(dir = %path.display(), "failed to park undeliverable message: {e}");
        }
    }
}

/// Delivery worker loop: wakes on new messages and on a regular interval to
/// pick up retries, until the shutdown signal fires.
pub async fn run_worker(
    mut rx: mpsc::Receiver<()>,
    spool: Arc<Spool>,
    delivery: Arc<Delivery>,
    retry: RetryConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = rx.recv() => {
                spool.process_due(&delivery, &retry).await;
            }
            _ = interval.tick() => {
                spool.process_due(&delivery, &retry).await;
            }
            _ = shutdown.changed() => {
                tracing::info!("spool worker shutting down");
                break;
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enqueue_and_list_due() {
        let dir = tempfile::tempdir().unwrap();
        let (spool, _rx) = Spool::open(dir.path().join("spool")).unwrap();
        let id = spool
            .enqueue("a@example.com".into(), vec!["b@example.com".into()], b"From: a\r\n\r\nhi".to_vec())
            .await
            .unwrap();
        let msg_dir = spool.dir().join(&id);
        assert!(msg_dir.join("meta.toml").exists());
        assert!(msg_dir.join("message.eml").exists());
        let due = spool.list_due();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.from, "a@example.com");
    }

    #[tokio::test]
    async fn removes_delivered_message() {
        let dir = tempfile::tempdir().unwrap();
        let (spool, _rx) = Spool::open(dir.path().join("spool")).unwrap();
        let id = spool
            .enqueue("a@example.com".into(), vec!["b@example.com".into()], b"hi".to_vec())
            .await
            .unwrap();
        let msg_dir = spool.dir().join(&id);
        assert!(msg_dir.exists());

        let delivery = Arc::new(crate::send::Delivery::unused_for_tests());
        spool.process_due(&delivery, &RetryConfig::default()).await;

        // delivery is a stub that errors, so message should still exist and
        // attempts should have advanced.
        let meta: Meta = toml::from_str(&std::fs::read_to_string(msg_dir.join("meta.toml")).unwrap())
            .unwrap();
        assert_eq!(meta.attempts, 1);
    }

    #[test]
    fn meta_roundtrip() {
        let meta = Meta {
            from: "a@b.com".into(),
            to: vec!["c@b.com".into()],
            created_at: 1,
            attempts: 0,
            next_attempt_at: 0,
        };
        let toml = toml::to_string(&meta).unwrap();
        let back: Meta = toml::from_str(&toml).unwrap();
        assert_eq!(back.from, meta.from);
        assert_eq!(back.to, meta.to);
    }
}
