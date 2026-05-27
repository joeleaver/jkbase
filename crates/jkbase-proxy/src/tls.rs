use anyhow::{Context, Result};
use instant_acme::{Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::ServerConfig;
use tracing::info;

#[derive(Clone)]
pub struct TlsConfig {
    pub domain: String,
    pub cert_dir: PathBuf,
    pub cloudflare_token: String,
    pub cloudflare_zone_id: String,
    pub acme_email: String,
}

pub async fn load_or_provision_tls(config: &TlsConfig) -> Result<Arc<ServerConfig>> {
    let cert_path = config.cert_dir.join("fullchain.pem");
    let key_path = config.cert_dir.join("privkey.pem");

    if cert_path.exists() && key_path.exists() {
        if cert_needs_renewal(&cert_path)? {
            info!("TLS certificate expiring soon, re-provisioning");
        } else {
            info!("loading existing TLS certificate");
            match load_tls_config(&cert_path, &key_path) {
                Ok(tls) => return Ok(tls),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load existing cert, will re-provision");
                }
            }
        }
    }

    info!("provisioning TLS certificate via ACME DNS-01");
    provision_cert(config).await?;
    load_tls_config(&cert_path, &key_path)
}

pub fn spawn_renewal_task(config: TlsConfig, tls_config: Arc<std::sync::RwLock<Arc<ServerConfig>>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;

            let cert_path = config.cert_dir.join("fullchain.pem");
            let needs_renewal = cert_needs_renewal(&cert_path).unwrap_or(true);

            if needs_renewal {
                info!("TLS certificate renewal triggered");
                match load_or_provision_tls(&config).await {
                    Ok(new_config) => {
                        let mut writer = tls_config.write().unwrap();
                        *writer = new_config;
                        info!("TLS certificate renewed and loaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "TLS certificate renewal failed, will retry");
                    }
                }
            }
        }
    });
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

fn cert_needs_renewal(cert_path: &Path) -> Result<bool> {
    let metadata = std::fs::metadata(cert_path)?;
    let modified = metadata.modified()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    Ok(age > std::time::Duration::from_secs(60 * 24 * 60 * 60))
}

async fn provision_cert(config: &TlsConfig) -> Result<()> {
    tokio::fs::create_dir_all(&config.cert_dir).await?;

    let (account, _credentials) = Account::builder()
        .context("failed to create ACME account builder")?
        .create(
            &NewAccount {
                contact: &[&format!("mailto:{}", config.acme_email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url().to_string(),
            None,
        )
        .await
        .context("failed to create ACME account")?;

    let wildcard = format!("*.{}", config.domain);
    let identifiers = vec![
        Identifier::Dns(config.domain.clone()),
        Identifier::Dns(wildcard),
    ];

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("failed to create ACME order")?;

    let mut cf_record_ids: Vec<String> = Vec::new();

    let mut authorizations = order.authorizations();
    while let Some(auth_result) = authorizations.next().await {
        let mut auth = auth_result.context("failed to get authorization")?;

        let mut challenge = auth
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge found"))?;

        let dns_value = challenge.key_authorization().dns_value();
        info!("setting DNS-01 challenge TXT record");

        let record_id = cloudflare_create_txt(
            &config.cloudflare_token,
            &config.cloudflare_zone_id,
            &format!("_acme-challenge.{}", config.domain),
            &dns_value,
        )
        .await?;
        cf_record_ids.push(record_id);

        info!("waiting for DNS propagation...");
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;

        challenge
            .set_ready()
            .await
            .context("failed to mark challenge ready")?;
    }
    drop(authorizations);

    info!("waiting for order to become ready...");
    order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await
        .context("order did not become ready")?;

    let key_pair = KeyPair::generate()?;
    let domain_names: Vec<String> = identifiers
        .iter()
        .filter_map(|id| match id {
            Identifier::Dns(d) => Some(d.clone()),
            _ => None,
        })
        .collect();
    let mut params = CertificateParams::new(domain_names)?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;

    order
        .finalize_csr(csr.der())
        .await
        .context("failed to finalize order")?;

    info!("waiting for certificate...");
    let cert_chain = order
        .poll_certificate(&instant_acme::RetryPolicy::default())
        .await
        .context("failed to get certificate")?;

    tokio::fs::write(config.cert_dir.join("fullchain.pem"), &cert_chain).await?;
    tokio::fs::write(config.cert_dir.join("privkey.pem"), key_pair.serialize_pem()).await?;

    info!("TLS certificate provisioned and saved");

    for record_id in &cf_record_ids {
        let _ = cloudflare_delete_txt(
            &config.cloudflare_token,
            &config.cloudflare_zone_id,
            record_id,
        )
        .await;
    }

    Ok(())
}

async fn cloudflare_create_txt(
    token: &str,
    zone_id: &str,
    name: &str,
    content: &str,
) -> Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 120,
        }))
        .send()
        .await
        .context("failed to create Cloudflare TXT record")?;

    let body: serde_json::Value = resp.json().await?;
    if !body["success"].as_bool().unwrap_or(false) {
        anyhow::bail!(
            "Cloudflare API error: {}",
            serde_json::to_string_pretty(&body["errors"])?
        );
    }

    body["result"]["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("no record ID in Cloudflare response"))
}

async fn cloudflare_delete_txt(token: &str, zone_id: &str, record_id: &str) -> Result<()> {
    let client = reqwest::Client::new();
    client
        .delete(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .context("failed to delete Cloudflare TXT record")?;
    Ok(())
}
