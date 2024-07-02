use std::{net::SocketAddr, time::Duration};

use assh::{side::server::Server, Session};
use assh_auth::handler::{none, Auth};
use assh_connect::{channel, connect::channel_open::Outcome};

use async_compat::CompatExt;
use clap::Parser;
use color_eyre::eyre;
use futures::{
    io::{BufReader, BufWriter},
    AsyncReadExt, AsyncWriteExt, FutureExt, StreamExt,
};
use ssh_packet::connect;
use tokio::{net::TcpListener, task};

const DELAY: Duration = Duration::from_millis(50);
const CLEAR: &str = "\x1B[2J";
const FRAMES: &[&str] = &[
    include_str!("parrot-server/0.txt"),
    include_str!("parrot-server/1.txt"),
    include_str!("parrot-server/2.txt"),
    include_str!("parrot-server/3.txt"),
    include_str!("parrot-server/4.txt"),
    include_str!("parrot-server/5.txt"),
    include_str!("parrot-server/6.txt"),
    include_str!("parrot-server/7.txt"),
    include_str!("parrot-server/8.txt"),
    include_str!("parrot-server/9.txt"),
];

/// An `assh` server example, providing a parrot animation on connection.
#[derive(Debug, Parser)]
pub struct Args {
    /// The address to bind the server on.
    address: SocketAddr,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    let keys = vec![ssh_key::private::PrivateKey::random(
        &mut rand::thread_rng(),
        ssh_key::Algorithm::Ed25519,
    )
    .expect("Cannot generate private keys")];
    let listener = TcpListener::bind(args.address).await?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let keys = keys.clone();

        task::spawn(async move {
            let stream = BufReader::new(BufWriter::new(stream.compat()));

            let mut session = Session::new(
                stream,
                Server {
                    keys,
                    ..Default::default()
                },
            )
            .await?;

            tracing::info!("Successfully connected to `{}`", session.peer_id());

            let connect = session
                .handle(
                    Auth::new(assh_connect::Service)
                        .banner("Welcome, and get parrot'd\r\n")
                        .none(|_| none::Response::Accept),
                )
                .await?;

            connect
                .on_channel_open(|_, mut channel: channel::Channel| {
                    task::spawn(async move {
                        channel
                            .requests()
                            .take_while(|request| {
                                futures::future::ready(matches!(
                                    request.ctx(),
                                    connect::ChannelRequestContext::Shell
                                        | connect::ChannelRequestContext::Exec { .. }
                                        | connect::ChannelRequestContext::Subsystem { .. }
                                ))
                            })
                            .for_each(|request| async {
                                request.accept().await;
                            })
                            .await;

                        let mut writer = channel.as_writer();
                        let mut reader = channel.as_reader();

                        for frame in FRAMES.iter().cycle() {
                            let mut read = [0u8; 1];

                            futures::select_biased! {
                                _ = tokio::time::sleep(DELAY).fuse() => {
                                    writer.write_all(CLEAR.as_bytes()).await?;
                                    writer.write_all(frame.as_bytes()).await?;
                                    writer.flush().await?;
                                }
                                len = reader.read(&mut read).fuse() => {
                                    if matches!(len, Ok(len) if len > 0 && read[0] == b'q') {
                                        break;
                                    }
                                }
                            }
                        }

                        Ok::<_, eyre::Error>(())
                    });

                    Outcome::Accept
                })
                .spin()
                .await?;

            Ok::<_, eyre::Error>(())
        });
    }
}
