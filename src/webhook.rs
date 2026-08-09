//! Signed, durable, at-least-once webhook delivery runtime.

use std::{collections::HashSet, time::Duration};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, Payload},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::Sha256;
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    config::{KeyRing, WebhookConfig},
    store::{
        AuthEvent, EncryptedWebhookSecret, IdentifierValue, Store, WebhookDeliveryRecord,
        WebhookDeliveryStatusRecord, WebhookManagementSourceRecord, WebhookRecord,
        WebhookStatusRecord, now,
    },
};

const WEBHOOK_SECRET_AAD_VERSION: &str = "rustyauth-webhook-secret-v1";
const MAX_ATTEMPTS: u32 = 8;
const DELIVERY_TIMEOUT_SECONDS: u64 = 10;

#[derive(Clone)]
pub struct WebhookRuntime {
    store: Store,
    keys: KeyRing,
    client: reqwest::Client,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryEnvelope<'a> {
    version: &'static str,
    delivery_id: Uuid,
    event: &'a AuthEvent,
}

impl WebhookRuntime {
    pub fn new(store: Store, keys: KeyRing) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECONDS))
            .user_agent(format!("rustyauth-webhooks/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build webhook HTTP client")?;
        Ok(Self {
            store,
            keys,
            client,
        })
    }

    pub async fn reconcile_configuration(&self, desired: &[WebhookConfig]) -> Result<()> {
        let desired_ids = desired
            .iter()
            .map(|config| config.id.as_str())
            .collect::<HashSet<_>>();
        for existing in self.store.webhooks().await? {
            if existing.management_source == WebhookManagementSourceRecord::Configuration
                && !desired_ids.contains(existing.id.as_str())
            {
                self.store.remove_webhook(&existing.id).await?;
            }
        }
        for config in desired {
            let timestamp = now();
            let record = match self.store.webhook(&config.id).await? {
                Some(mut record) => {
                    if record.management_source != WebhookManagementSourceRecord::Configuration {
                        bail!(
                            "configuration webhook id {} conflicts with a dashboard-managed destination",
                            config.id
                        );
                    }
                    record.name = config.name.clone();
                    record.url = config.endpoint.to_string();
                    record.status = if config.enabled {
                        WebhookStatusRecord::Active
                    } else {
                        WebhookStatusRecord::Paused
                    };
                    record.event_types = config.event_types.clone();
                    record.updated_at = timestamp;
                    record
                }
                None => {
                    let secret = new_signing_secret();
                    let record = WebhookRecord {
                        id: config.id.clone(),
                        name: config.name.clone(),
                        url: config.endpoint.to_string(),
                        status: if config.enabled {
                            WebhookStatusRecord::Active
                        } else {
                            WebhookStatusRecord::Paused
                        },
                        event_types: config.event_types.clone(),
                        secret: seal_secret(&self.keys, &config.id, secret.expose_secret())?,
                        secret_hint: secret_hint(secret.expose_secret()),
                        management_source: WebhookManagementSourceRecord::Configuration,
                        created_at: timestamp,
                        updated_at: timestamp,
                        last_delivery_at: None,
                    };
                    self.store
                        .set_webhook_cursor(&record.id, self.store.latest_event_sequence().await?)
                        .await?;
                    record
                }
            };
            self.store
                .put_webhook(&record, "webhook.configuration.reconciled")
                .await?;
        }
        Ok(())
    }

    pub async fn create_dashboard_webhook(
        &self,
        name: String,
        url: String,
        event_types: Vec<String>,
    ) -> Result<(WebhookRecord, SecretString)> {
        let id = Uuid::new_v4().to_string();
        let timestamp = now();
        let secret = new_signing_secret();
        let record = WebhookRecord {
            id,
            name,
            url,
            status: WebhookStatusRecord::Active,
            event_types,
            secret: seal_secret(&self.keys, "pending", "pending")?,
            secret_hint: secret_hint(secret.expose_secret()),
            management_source: WebhookManagementSourceRecord::Dashboard,
            created_at: timestamp,
            updated_at: timestamp,
            last_delivery_at: None,
        };
        let mut record = record;
        record.secret = seal_secret(&self.keys, &record.id, secret.expose_secret())?;
        self.store
            .set_webhook_cursor(&record.id, self.store.latest_event_sequence().await?)
            .await?;
        self.store.put_webhook(&record, "webhook.created").await?;
        Ok((record, secret))
    }

    pub async fn rotate_secret(&self, id: &str) -> Result<(WebhookRecord, SecretString)> {
        let mut record = self
            .store
            .webhook(id)
            .await?
            .context("webhook destination is missing")?;
        let secret = new_signing_secret();
        record.secret = seal_secret(&self.keys, id, secret.expose_secret())?;
        record.secret_hint = secret_hint(secret.expose_secret());
        record.updated_at = now();
        self.store
            .put_webhook(&record, "webhook.signing_secret.rotated")
            .await?;
        Ok((record, secret))
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.dispatch_once().await {
                        tracing::error!(error = %error, "webhook delivery pass failed");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    pub async fn dispatch_once(&self) -> Result<()> {
        for webhook in self.store.webhooks().await? {
            if webhook.status != WebhookStatusRecord::Paused {
                self.dispatch_webhook(webhook).await?;
            }
        }
        Ok(())
    }

    pub async fn test_delivery(&self, webhook_id: &str) -> Result<WebhookDeliveryRecord> {
        let webhook = self
            .store
            .webhook(webhook_id)
            .await?
            .context("webhook destination is missing")?;
        let event = AuthEvent {
            sequence: 0,
            id: Uuid::new_v4(),
            tenant_id: "test".into(),
            event_type: "webhook.test".into(),
            subject: None,
            occurred_at: now(),
            data: serde_json::json!({"test": true}),
        };
        self.send_direct(&webhook, &event).await
    }

    /// Sends an ephemeral verification instruction only to destinations that
    /// explicitly subscribed to the exact sensitive event type. The raw code is
    /// never appended to the auth event log or stored in delivery metadata.
    pub async fn deliver_identifier_verification(
        &self,
        challenge_id: Uuid,
        identifier: &IdentifierValue,
        raw_code: &str,
        expires_at: u64,
    ) -> Result<usize> {
        let event_type = format!("identifier.{}.verification", identifier.kind.as_str());
        let event = AuthEvent {
            sequence: 0,
            id: Uuid::new_v4(),
            tenant_id: "verification-delivery".into(),
            event_type: event_type.clone(),
            subject: None,
            occurred_at: now(),
            data: serde_json::json!({
                "challengeId": challenge_id,
                "destination": identifier.value,
                "code": raw_code,
                "expiresAt": expires_at,
            }),
        };
        let mut succeeded = 0_usize;
        for webhook in self.store.webhooks().await? {
            if webhook.status == WebhookStatusRecord::Paused
                || !webhook.event_types.iter().any(|value| value == &event_type)
            {
                continue;
            }
            let delivery = self.send_direct(&webhook, &event).await?;
            succeeded += usize::from(delivery.status == WebhookDeliveryStatusRecord::Succeeded);
        }
        Ok(succeeded)
    }

    pub async fn replay_delivery(&self, delivery_id: Uuid) -> Result<WebhookDeliveryRecord> {
        let original = self
            .store
            .webhook_delivery(delivery_id)
            .await?
            .context("webhook delivery is missing")?;
        let webhook = self
            .store
            .webhook(&original.webhook_id)
            .await?
            .context("webhook destination is missing")?;
        let event = self
            .store
            .events(original.event_sequence.saturating_sub(1), 1)
            .await?
            .into_iter()
            .find(|event| event.sequence == original.event_sequence)
            .context("original webhook event is no longer retained")?;
        self.send_direct(&webhook, &event).await
    }

    async fn send_direct(
        &self,
        webhook: &WebhookRecord,
        event: &AuthEvent,
    ) -> Result<WebhookDeliveryRecord> {
        let mut delivery = WebhookDeliveryRecord {
            id: Uuid::new_v4(),
            webhook_id: webhook.id.clone(),
            event_sequence: event.sequence,
            event_id: event.id,
            event_type: event.event_type.clone(),
            status: WebhookDeliveryStatusRecord::Pending,
            attempt_count: 0,
            response_status: None,
            latency_milliseconds: 0,
            created_at: now(),
            next_attempt_at: None,
            completed_at: None,
            error_class: String::new(),
        };
        let secret = open_secret(&self.keys, &webhook.id, &webhook.secret)?;
        let started = std::time::Instant::now();
        let attempt = self
            .send(webhook, &delivery, event, secret.expose_secret())
            .await;
        delivery.attempt_count = 1;
        delivery.latency_milliseconds =
            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        delivery.completed_at = Some(now());
        match attempt {
            Ok(status) if status.is_success() => {
                delivery.status = WebhookDeliveryStatusRecord::Succeeded;
                delivery.response_status = Some(status.as_u16());
            }
            Ok(status) => {
                delivery.status = WebhookDeliveryStatusRecord::Failed;
                delivery.response_status = Some(status.as_u16());
                delivery.error_class = "http_status".into();
            }
            Err(error) => {
                tracing::warn!(webhook_id = %webhook.id, delivery_id = %delivery.id, error = %error, "direct webhook attempt failed");
                delivery.status = WebhookDeliveryStatusRecord::Failed;
                delivery.error_class = "transport".into();
            }
        }
        self.store.put_webhook_delivery(&delivery).await?;
        Ok(delivery)
    }

    async fn dispatch_webhook(&self, mut webhook: WebhookRecord) -> Result<()> {
        let cursor = self.store.webhook_cursor(&webhook.id).await?;
        let Some(event) = self.store.events(cursor, 1).await?.into_iter().next() else {
            return Ok(());
        };
        // Analytics bookkeeping is deliberately written to the durable event
        // log so projection survives restarts. It is an internal stream and
        // must never be delivered to wildcard webhooks: doing so would create
        // an unbounded delivery -> metric event -> delivery loop.
        if is_internal_analytics_event(&event.event_type) {
            self.store
                .set_webhook_cursor(&webhook.id, event.sequence)
                .await?;
            return Ok(());
        }
        if !webhook
            .event_types
            .iter()
            .any(|event_type| event_type == "*" || event_type == &event.event_type)
        {
            self.store
                .set_webhook_cursor(&webhook.id, event.sequence)
                .await?;
            return Ok(());
        }
        let mut delivery = match self
            .store
            .webhook_delivery_for_event(&webhook.id, event.sequence)
            .await?
        {
            Some(delivery) => delivery,
            None => WebhookDeliveryRecord {
                id: Uuid::new_v4(),
                webhook_id: webhook.id.clone(),
                event_sequence: event.sequence,
                event_id: event.id,
                event_type: event.event_type.clone(),
                status: WebhookDeliveryStatusRecord::Pending,
                attempt_count: 0,
                response_status: None,
                latency_milliseconds: 0,
                created_at: now(),
                next_attempt_at: None,
                completed_at: None,
                error_class: String::new(),
            },
        };
        if delivery.status == WebhookDeliveryStatusRecord::Succeeded
            || delivery.status == WebhookDeliveryStatusRecord::Failed
        {
            self.store
                .set_webhook_cursor(&webhook.id, event.sequence)
                .await?;
            return Ok(());
        }
        if delivery.next_attempt_at.is_some_and(|at| at > now()) {
            return Ok(());
        }
        self.store.put_webhook_delivery(&delivery).await?;
        let secret = open_secret(&self.keys, &webhook.id, &webhook.secret)?;
        let started = std::time::Instant::now();
        let attempt = self
            .send(&webhook, &delivery, &event, secret.expose_secret())
            .await;
        delivery.attempt_count = delivery.attempt_count.saturating_add(1);
        delivery.latency_milliseconds =
            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        match attempt {
            Ok(status) if status.is_success() => {
                delivery.status = WebhookDeliveryStatusRecord::Succeeded;
                delivery.response_status = Some(status.as_u16());
                delivery.completed_at = Some(now());
                delivery.next_attempt_at = None;
                delivery.error_class.clear();
                webhook.last_delivery_at = delivery.completed_at;
                if webhook.status == WebhookStatusRecord::Failing {
                    webhook.status = WebhookStatusRecord::Active;
                }
            }
            Ok(status) => {
                delivery.response_status = Some(status.as_u16());
                delivery.error_class = "http_status".into();
                let retryable =
                    matches!(status.as_u16(), 408 | 425 | 429) || status.is_server_error();
                schedule_or_fail(&mut delivery, retryable);
            }
            Err(error) => {
                tracing::warn!(webhook_id = %webhook.id, delivery_id = %delivery.id, error = %error, "webhook attempt failed");
                delivery.error_class = "transport".into();
                schedule_or_fail(&mut delivery, true);
            }
        }
        if delivery.status == WebhookDeliveryStatusRecord::Failed {
            webhook.status = WebhookStatusRecord::Failing;
        }
        webhook.updated_at = now();
        self.store.put_webhook_delivery(&delivery).await?;
        self.store.update_webhook_runtime(&webhook).await?;
        if matches!(
            delivery.status,
            WebhookDeliveryStatusRecord::Succeeded | WebhookDeliveryStatusRecord::Failed
        ) {
            self.store
                .set_webhook_cursor(&webhook.id, event.sequence)
                .await?;
        }
        Ok(())
    }

    async fn send(
        &self,
        webhook: &WebhookRecord,
        delivery: &WebhookDeliveryRecord,
        event: &AuthEvent,
        secret: &str,
    ) -> Result<reqwest::StatusCode> {
        let body = serde_json::to_vec(&DeliveryEnvelope {
            version: "1",
            delivery_id: delivery.id,
            event,
        })?;
        let timestamp = now().to_string();
        let signature = delivery_signature(secret, &timestamp, &body)?;
        let response = self
            .client
            .post(&webhook.url)
            .header("content-type", "application/json")
            .header("x-rustyauth-delivery", delivery.id.to_string())
            .header("x-rustyauth-event", event.event_type.as_str())
            .header("x-rustyauth-timestamp", &timestamp)
            .header("x-rustyauth-signature", format!("v1={signature}"))
            .body(body)
            .send()
            .await
            .context("send webhook request")?;
        Ok(response.status())
    }
}

fn schedule_or_fail(delivery: &mut WebhookDeliveryRecord, retryable: bool) {
    if retryable && delivery.attempt_count < MAX_ATTEMPTS {
        delivery.status = WebhookDeliveryStatusRecord::Retrying;
        let exponent = delivery.attempt_count.saturating_sub(1).min(11);
        delivery.next_attempt_at = Some(now().saturating_add(1_u64 << exponent));
        delivery.completed_at = None;
    } else {
        delivery.status = WebhookDeliveryStatusRecord::Failed;
        delivery.next_attempt_at = None;
        delivery.completed_at = Some(now());
    }
}

fn is_internal_analytics_event(event_type: &str) -> bool {
    event_type.starts_with("analytics.")
}

fn new_signing_secret() -> SecretString {
    SecretString::from(format!(
        "whsec_{}",
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    ))
}

fn secret_hint(secret: &str) -> String {
    secret
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn seal_secret(keys: &KeyRing, webhook_id: &str, secret: &str) -> Result<EncryptedWebhookSecret> {
    let (key_id, key) = keys.active();
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key length is fixed");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: secret.as_bytes(),
                aad: secret_aad(webhook_id).as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt webhook signing secret"))?;
    Ok(EncryptedWebhookSecret {
        wrapping_key_id: key_id.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

fn open_secret(
    keys: &KeyRing,
    webhook_id: &str,
    encrypted: &EncryptedWebhookSecret,
) -> Result<SecretString> {
    let key = keys
        .get(&encrypted.wrapping_key_id)
        .context("webhook signing secret wrapping key is unavailable")?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&encrypted.nonce)
        .context("webhook signing secret nonce is invalid")?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("webhook signing secret nonce has wrong length"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .context("webhook signing secret ciphertext is invalid")?;
    let plaintext = Aes256Gcm::new_from_slice(key)
        .expect("AES-256 key length is fixed")
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ciphertext,
                aad: secret_aad(webhook_id).as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("webhook signing secret authentication failed"))?;
    Ok(SecretString::from(
        String::from_utf8(plaintext).context("webhook signing secret is not UTF-8")?,
    ))
}

fn secret_aad(webhook_id: &str) -> String {
    format!("{WEBHOOK_SECRET_AAD_VERSION}\0{webhook_id}")
}

fn delivery_signature(secret: &str, timestamp: &str, body: &[u8]) -> Result<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid webhook signing secret"))?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_bind_timestamp_and_exact_body() {
        let first = delivery_signature("whsec_test", "100", br#"{"ok":true}"#).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(
            first,
            delivery_signature("whsec_test", "100", br#"{"ok":true}"#).unwrap()
        );
        assert_ne!(
            first,
            delivery_signature("whsec_test", "101", br#"{"ok":true}"#).unwrap()
        );
        assert_ne!(
            first,
            delivery_signature("whsec_test", "100", br#"{"ok":false}"#).unwrap()
        );
    }

    #[test]
    fn wildcard_delivery_cannot_recurse_through_internal_analytics_events() {
        assert!(is_internal_analytics_event(
            "analytics.webhook.delivery.succeeded"
        ));
        assert!(!is_internal_analytics_event("authentication.completed"));
    }

    #[test]
    fn retry_schedule_is_bounded_and_terminal() {
        let mut delivery = WebhookDeliveryRecord {
            id: Uuid::new_v4(),
            webhook_id: "hook".into(),
            event_sequence: 1,
            event_id: Uuid::new_v4(),
            event_type: "identity.created".into(),
            status: WebhookDeliveryStatusRecord::Pending,
            attempt_count: 1,
            response_status: None,
            latency_milliseconds: 0,
            created_at: now(),
            next_attempt_at: None,
            completed_at: None,
            error_class: String::new(),
        };
        schedule_or_fail(&mut delivery, true);
        assert_eq!(delivery.status, WebhookDeliveryStatusRecord::Retrying);
        delivery.attempt_count = MAX_ATTEMPTS;
        schedule_or_fail(&mut delivery, true);
        assert_eq!(delivery.status, WebhookDeliveryStatusRecord::Failed);
        assert!(delivery.completed_at.is_some());
    }
}
