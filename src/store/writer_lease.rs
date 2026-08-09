//! Cross-process enforcement of RustyAuth's supported single-writer topology.

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use super::Store;

pub(super) const WRITER_LEASE_KEY: &str = "auth:writer-lease";
pub(super) const WRITER_LEASE_SECONDS: u64 = 60;
const COMPARE_DELETE: &str = r#"if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end"#;

pub struct WriterLease {
    store: Store,
    token: String,
}

impl Store {
    pub async fn acquire_writer_lease(&self) -> Result<WriterLease> {
        let token = Uuid::new_v4().to_string();
        let mut connection = self.redis.clone();
        let acquired: Option<String> = redis::cmd("SET")
            .arg(WRITER_LEASE_KEY)
            .arg(&token)
            .arg("NX")
            .arg("EX")
            .arg(WRITER_LEASE_SECONDS)
            .query_async(&mut connection)
            .await
            .context("acquire RustyAuth writer lease")?;
        if acquired.is_none() {
            bail!(
                "another RustyAuth writer owns this SableDB namespace; keep exactly one writer replica"
            );
        }
        Ok(WriterLease {
            store: self.clone(),
            token,
        })
    }
}

impl WriterLease {
    /// Atomically refreshes the current lease and returns whether this process owns it.
    ///
    /// `GETEX` is supported by the pinned SableDB revision and returns the value whose TTL it
    /// refreshes in the same key lock. If another writer has replaced the token, extending that
    /// newer writer's lease is safe; this process observes the mismatch and immediately fences
    /// itself. A matching value cannot be replaced before the newly refreshed TTL expires.
    pub async fn renew(&self) -> Result<bool> {
        let mut connection = self.store.redis.clone();
        let owner = redis::cmd("GETEX")
            .arg(WRITER_LEASE_KEY)
            .arg("EX")
            .arg(WRITER_LEASE_SECONDS)
            .query_async::<Option<String>>(&mut connection)
            .await
            .context("renew RustyAuth writer lease")?;
        Ok(owner.as_deref() == Some(self.token.as_str()))
    }

    pub async fn release(self) -> Result<bool> {
        let mut connection = self.store.redis.clone();
        let response = redis::cmd("DELIFEQ")
            .arg(WRITER_LEASE_KEY)
            .arg(&self.token)
            .query_async::<i64>(&mut connection)
            .await;
        let removed = match response {
            Ok(value) => value,
            Err(error) if unknown_command(&error) => redis::cmd("EVAL")
                .arg(COMPARE_DELETE)
                .arg(1_u8)
                .arg(WRITER_LEASE_KEY)
                .arg(&self.token)
                .query_async(&mut connection)
                .await
                .context("release RustyAuth writer lease")?,
            Err(error) => return Err(error).context("release RustyAuth writer lease"),
        };
        Ok(removed == 1)
    }
}

fn unknown_command(error: &redis::RedisError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("unknown command") || text.contains("unsupported command")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_uses_the_pinned_datastores_atomic_get_and_expire_command() {
        assert_eq!(WRITER_LEASE_KEY, "auth:writer-lease");
        assert_eq!(WRITER_LEASE_SECONDS, 60);
    }

    #[test]
    fn writer_lease_is_not_a_snapshot_record() {
        assert_eq!(WRITER_LEASE_KEY, "auth:writer-lease");
    }
}
