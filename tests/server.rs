#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;

use async_std::{net::TcpListener, process::Command, stream::StreamExt, task::JoinHandle};
use rstest::rstest;
use ssh_packet::trans::{Debug, ServiceAccept};

use assh::{
    server::{Config, Session},
    Message, Result,
};

async fn server() -> Result<(SocketAddr, JoinHandle<Result<Message>>)> {
    let socket = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = socket.local_addr()?;

    let handle = async_std::task::spawn_local(async move {
        let stream = socket.incoming().next().await.unwrap()?;

        let config = Config {
            keys: vec![ssh_key::PrivateKey::random(
                &mut rand::thread_rng(),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap()],
            ..Default::default()
        };
        let mut session = Session::new(stream, config).await?;

        let Message::ServiceRequest(request) = session.recv().await? else {
            panic!("Unexpected message");
        };

        session
            .send(&Debug {
                message: "hello world".to_string().into(),
                language: Default::default(),
                always_display: true.into(),
            })
            .await?;
        session
            .send(&ServiceAccept {
                service_name: request.service_name,
            })
            .await?;

        session.recv().await
    });

    tracing::info!("Binding server on port {}", addr.port());

    Ok((addr, handle))
}

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
    tracing_subscriber::fmt().try_init().ok();

    println!("Parameters: cipher::{cipher}, mac::{mac}, kex::{kex}");

    let (addr, handle) = server().await?;

    let mut client = Command::new("ssh")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg(format!("-oKexAlgorithms={kex}"))
        .arg(format!("-c{cipher}"))
        .arg(format!("-m{mac}"))
        .arg(format!("-p{}", addr.port()))
        .arg("-vvv")
        .arg("user@127.0.0.1")
        .arg("/bin/bash")
        .spawn()?;

    let message = handle.await?;
    let status = client.status().await?;

    tracing::info!("message: {message:?}, {status}");

    assert!(matches!(message, Message::AuthRequest { .. }));

    Ok(())
}
