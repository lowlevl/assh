use russh_keys::key;
use test_log::test;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

use assh::server::{Config, Session};

#[ignore]
#[test(tokio::test)]
async fn with_russh() -> Result<(), Box<dyn std::error::Error>> {
    let socket = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = socket.local_addr()?.port();

    let handle = tokio::spawn(async move {
        let (stream, _) = socket.accept().await?;

        let config = Config {
            keys: vec![ssh_key::PrivateKey::random(
                &mut rand::thread_rng(),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap()],
            ..Default::default()
        };
        let mut session = Session::new(stream.compat(), config).await?;

        session.recv().await
    });

    tracing::info!("Binding server on port {port}");

    struct Client;
    #[async_trait::async_trait]
    impl russh::client::Handler for Client {
        type Error = russh::Error;

        async fn check_server_key(self, _: &key::PublicKey) -> Result<(Self, bool), Self::Error> {
            Ok((self, true))
        }
    }

    let client = Client;
    let mut session =
        russh::client::connect(Default::default(), ("127.0.0.1", port), client).await?;

    session.authenticate_none("user").await?;

    let message = handle.await??;
    tracing::info!("message: {message:?}");
    Ok(())
}
