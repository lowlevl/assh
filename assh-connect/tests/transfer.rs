use assh::{
    Result,
    algorithm::Key,
    side::{
        client::Client,
        server::{PrivateKey, Server},
    },
};
use assh_connect::{
    channel,
    channel_open::{self, ChannelOpenContext},
};

use async_compat::{Compat, CompatExt};
use futures::{AsyncRead, AsyncReadExt, FutureExt, TryFutureExt, TryStreamExt, future::BoxFuture};
use rand::{RngExt, SeedableRng};
use sha1::{Digest, Sha1};
use tokio::io::{BufStream, DuplexStream};
use tracing::Instrument;

type IO = Compat<BufStream<DuplexStream>>;

async fn sha1(mut rdr: impl AsyncRead + Unpin) -> std::io::Result<Sha1> {
    let mut digest = Sha1::new();
    let mut buf = [0u8; 65535];

    loop {
        let count = rdr.read(&mut buf[..]).await?;
        if count == 0 {
            break;
        }

        digest.update(&buf[..count]);
    }

    Ok(digest)
}

async fn io<S, C>(serverside: S, clientside: C) -> Result<(), eyre::Error>
where
    S: Fn(channel::Channel<'_, IO, Server>) -> BoxFuture<'_, ()>,
    C: Fn(channel::Channel<'_, IO, Client>) -> BoxFuture<'_, ()>,
{
    let duplex = tokio::io::duplex(ssh_packet::Packet::MAX_SIZE * 16);
    let keys = vec![PrivateKey::random(&mut rand::rng(), Key::Ed25519)?];

    tokio::try_join!(
        async {
            let server = Server {
                keys,
                ..Default::default()
            };
            let server = assh::Session::new(BufStream::new(duplex.0).compat(), server).await?;

            let connect = server.handle(assh_connect::Service).await?;
            {
                let channel = connect
                    .channel_opens()
                    .try_next()
                    .await?
                    .expect("Disconnected before opening at least one channel")
                    .accept()
                    .await?;

                serverside(channel)
                    .instrument(tracing::span!(tracing::Level::INFO, "server"))
                    .await;
            }

            Ok(())
        }
        .inspect_err(|err: &eyre::Error| tracing::error!("An error occured server-side: {err}")),
        async {
            let client = Client::default();
            let client = assh::Session::new(BufStream::new(duplex.1).compat(), client).await?;

            let connect = client.request(assh_connect::Service).await?;
            let channel_open::Response::Success(channel) =
                connect.channel_open(ChannelOpenContext::Session).await?
            else {
                panic!("Channel opening rejected server-side")
            };

            clientside(channel)
                .instrument(tracing::span!(tracing::Level::INFO, "client"))
                .await;

            Ok(())
        }
        .inspect_err(|err: &eyre::Error| tracing::error!("An error occured client-side: {err}")),
    )?;

    Ok(())
}

#[tokio::test]
async fn small() -> Result<(), eyre::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    io(
        |channel| {
            async move {
                futures::io::copy(&mut channel.as_reader(), &mut channel.as_writer())
                    .await
                    .unwrap();

                channel.eof().await.unwrap();
            }
            .boxed()
        },
        |channel| {
            async move {
                let mut rng = rand::rngs::SmallRng::seed_from_u64(rand::rng().random());

                let (sent, recvd) = tokio::join!(
                    async {
                        let mut sent = sha1::Sha1::new();

                        let buffer = rng.random::<[u8; 8192]>();
                        sent.update(buffer);

                        futures::io::copy(&mut &buffer[..], &mut channel.as_writer())
                            .await
                            .unwrap();

                        channel.eof().await.unwrap();

                        sent
                    },
                    async { sha1(&mut channel.as_reader()).await.unwrap() }
                );

                assert_eq!(sent.finalize(), recvd.finalize())
            }
            .boxed()
        },
    )
    .await
}

#[tokio::test]
async fn large() -> Result<(), eyre::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    io(
        |channel| {
            async move {
                futures::io::copy(&mut channel.as_reader(), &mut channel.as_writer())
                    .await
                    .unwrap();

                channel.eof().await.unwrap();
            }
            .boxed()
        },
        |channel| {
            async move {
                let mut rng = rand::rngs::SmallRng::seed_from_u64(rand::rng().random());

                let (sent, recvd) = tokio::join!(
                    async {
                        let mut sent = sha1::Sha1::new();

                        const BYTES_TO_SEND: u64 = 0xFFFFF * 2;
                        let mut current = 0;

                        while current < BYTES_TO_SEND {
                            let buffer = rng.random::<[u8; 65535]>();
                            sent.update(buffer);

                            current +=
                                futures::io::copy(&mut &buffer[..], &mut channel.as_writer())
                                    .await
                                    .unwrap();
                        }

                        channel.eof().await.unwrap();

                        sent
                    },
                    async { sha1(&mut channel.as_reader()).await.unwrap() }
                );

                assert_eq!(sent.finalize(), recvd.finalize())
            }
            .boxed()
        },
    )
    .await
}
