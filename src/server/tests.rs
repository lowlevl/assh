use async_std::{net::TcpListener, process::Command, stream::StreamExt};
use rstest::rstest;
use test_log::test;

use super::*;

#[test(rstest)]
async fn end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let socket = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = socket.local_addr()?.port();

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

        session.recv().await
    });

    tracing::info!("Binding server on port {port}");

    let mut client = Command::new("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg(format!("-p {port}"))
        .arg("user@127.0.0.1")
        .spawn()?;

    let message = handle.await?;
    let status = client.status().await?;

    tracing::info!("message: {message:?}, status: {status}");

    Ok(())
}
