#![allow(clippy::unwrap_used)]

use async_std::process::Command;
use rstest::rstest;

use assh::{Message, Result};

mod common;

#[rstest]
#[case("3des-cbc", "hmac-sha2-512", "curve25519-sha256")]
#[case("aes128-cbc", "hmac-sha2-512", "curve25519-sha256")]
#[case("aes192-cbc", "hmac-sha2-512", "curve25519-sha256")]
#[case("aes256-cbc", "hmac-sha2-512", "curve25519-sha256")]
#[case("3des-cbc", "hmac-sha2-512-etm@openssh.com", "curve25519-sha256")]
#[case("aes128-cbc", "hmac-sha2-512-etm@openssh.com", "curve25519-sha256")]
#[case("aes192-cbc", "hmac-sha2-512-etm@openssh.com", "curve25519-sha256")]
#[case("aes256-cbc", "hmac-sha2-512-etm@openssh.com", "curve25519-sha256")]
#[case("aes128-ctr", "hmac-sha1", "curve25519-sha256")]
#[case("aes192-ctr", "hmac-sha2-256", "curve25519-sha256")]
#[case("aes256-ctr", "hmac-sha2-512", "curve25519-sha256")]
#[case("aes128-ctr", "hmac-sha1-etm@openssh.com", "curve25519-sha256")]
#[case("aes192-ctr", "hmac-sha2-256-etm@openssh.com", "curve25519-sha256")]
#[case("aes256-ctr", "hmac-sha2-512-etm@openssh.com", "curve25519-sha256")]
async fn against_openssh_client(
    #[case] cipher: &str,
    #[case] mac: &str,
    #[case] kex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    let (addr, handle) = common::server().await?;

    tracing::info!("cipher::{cipher}, mac::{mac}, kex::{kex}, bound to {addr}");

    let mut client = Command::new("ssh")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oRekeyLimit=1K")
        .arg(format!("-oKexAlgorithms={kex}"))
        .arg(format!("-c{cipher}"))
        .arg(format!("-m{mac}"))
        .arg(format!("-p{}", addr.port()))
        .arg("user@127.0.0.1")
        .arg("/bin/bash")
        .spawn()?;

    let message = handle.await?;
    let status = client.status().await?;

    tracing::info!("message: {message:?}, {status}");

    assert!(matches!(message, Message::ChannelRequest { .. }));

    Ok(())
}
