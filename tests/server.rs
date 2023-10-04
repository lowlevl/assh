#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;

use async_std::{net::TcpListener, process::Command, stream::StreamExt, task::JoinHandle};
use rstest::rstest;
use ssh_packet::trans::{Debug, ServiceAccept};
use test_log::test;

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

#[test(rstest)]
async fn end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let (addr, handle) = server().await?;

    let mut client = Command::new("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg(format!("-p {}", addr.port()))
        .arg("-vvv")
        .arg("user@127.0.0.1")
        .arg("/bin/bash")
        .spawn()?;

    let message = handle.await?;
    let status = client.status().await?;

    tracing::info!("message: {message:?}, {status}");

    assert!(status.success());

    Ok(())
}
