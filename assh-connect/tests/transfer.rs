use assh::{
    side::{client::Client, server::Server},
    Result,
};
use assh_connect::{
    channel,
    connect::{self, channel_open},
};

use async_compat::CompatExt;
use futures::TryFutureExt;
use rand::{Rng, SeedableRng};
use sha1::Digest;
use ssh_key::{Algorithm, PrivateKey};
use tokio::io::BufStream;

async fn io<SFut, CFut>(
    mut serverside: impl Fn(channel::Channel) -> SFut,
    mut clientside: impl Fn(channel::Channel) -> CFut,
) -> Result<(), eyre::Error>
where
    SFut: futures::Future<Output = ()> + Send + 'static,
    CFut: futures::Future<Output = ()> + Send + 'static,
{
    let duplex = tokio::io::duplex(ssh_packet::PACKET_MAX_SIZE * 16);
    let keys = vec![PrivateKey::random(
        &mut rand::thread_rng(),
        Algorithm::Ed25519,
    )?];

    tokio::try_join!(
        async {
            let server = Server {
                keys,
                ..Default::default()
            };
            let mut server = assh::Session::new(BufStream::new(duplex.0).compat(), server).await?;

            let connect = server.handle(assh_connect::Service).await?;

            connect
                .on_channel_open(|_, channel: channel::Channel| {
                    tokio::spawn(serverside(channel));

                    channel_open::Outcome::Accept
                })
                .spin()
                .await?;

            Ok(())
        }
        .inspect_err(|err: &eyre::Error| tracing::error!("An error occured server-side: {err}")),
        async {
            let client = Client::default();
            let mut client = assh::Session::new(BufStream::new(duplex.1).compat(), client).await?;

            let mut connect = client.request(assh_connect::Service).await?;
            let channel_open::ChannelOpen::Accepted(channel) = connect
                .channel_open(connect::ChannelOpenContext::Session)
                .await?
            else {
                panic!("Channel opening rejected server-side")
            };

            tokio::join!(clientside(channel), async { connect.spin().await.unwrap() });

            Ok(())
        }
        .inspect_err(|err: &eyre::Error| tracing::error!("An error occured client-side: {err}")),
    )?;

    Ok(())
}

#[tokio::test]
async fn short() -> Result<(), eyre::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    io(
        |channel| async move {
            futures::io::copy(&mut channel.as_reader(), &mut channel.as_writer())
                .await
                .unwrap();

            channel.eof().await.unwrap();
        },
        |channel| async move {
            let mut rng = rand::rngs::StdRng::from_entropy();
            let (mut local, mut recvd) = (sha1::Sha1::new(), sha1::Sha1::new());

            tokio::join!(
                async {
                    let buffer = rng.gen::<[u8; 256]>();
                    local.update(buffer);

                    futures::io::copy(&mut &buffer[..], &mut channel.as_writer())
                        .await
                        .unwrap();

                    channel.eof().await.unwrap();
                },
                async {
                    futures::io::copy(
                        &mut channel.as_reader(),
                        &mut futures::io::AllowStdIo::new(&mut recvd),
                    )
                    .await
                    .unwrap();
                }
            );

            assert_eq!(local.finalize(), recvd.finalize())
        },
    )
    .await
}
