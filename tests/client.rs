#![allow(clippy::unwrap_used)]

use async_std::net::TcpStream;
use rstest::rstest;

use assh::{
    session::{client::Client, Session},
    Message, Result,
};
use ssh_packet::{trans::ServiceRequest, userauth::AuthRequest};

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
async fn end_to_end(
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

    let stream = TcpStream::connect(addr).await?;
    let mut client = Session::new(stream, Client::default()).await?;

    client
        .send(&ServiceRequest {
            service_name: "ssh-userauth".into(),
        })
        .await?;
    let Message::ServiceAccept(_) = client.recv().await? else {
        panic!("Service refused")
    };
    client
        .send(&AuthRequest {
            username: "user".into(),
            service_name: "?".into(),
            method: ssh_packet::userauth::AuthMethod::None,
        })
        .await?;

    let message = handle.await?;

    tracing::info!("message: {message:?}");

    assert!(matches!(message, Message::AuthRequest { .. }));

    Ok(())
}
