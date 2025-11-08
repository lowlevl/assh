use std::{net::SocketAddr, time::Duration};

use assh::{Session, side::server::Server};
use assh_auth::handler::{Auth, none};

use async_compat::CompatExt;
use clap::Parser;
use color_eyre::eyre;
use futures::{
    AsyncReadExt, AsyncWriteExt, FutureExt, TryFutureExt, TryStreamExt,
    io::{BufReader, BufWriter},
};
use ssh_key::PrivateKey;
use ssh_packet::connect::ChannelRequestContext;
use tokio::{
    net::{TcpListener, TcpStream},
    task,
};

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

async fn session(stream: TcpStream, keys: Vec<PrivateKey>) -> eyre::Result<()> {
    let stream = BufReader::new(BufWriter::new(stream.compat()));
    let session = Session::new(
        stream,
        Server {
            keys,
            ..Default::default()
        },
    )
    .await?;

    tracing::info!("Successfully connected to `{}`", session.peer_id());

    let authentication = Auth::new(assh_connect::Service)
        .banner("Welcome, and get parrot'd back\r\n")
        .none(|_| none::Response::Accept);
    let connect = std::sync::Arc::new(session.handle(authentication).await?);

    task::spawn({
        let connect = connect.clone();

        async move {
            connect
                .global_requests()
                .try_for_each(|request| async move {
                    tracing::info!("Received Global request: {:?}", request.cx());

                    request.reject().await
                })
                .await
        }
    });

    connect
        .channel_opens()
        .err_into()
        .try_for_each_concurrent(None, |request| async {
            let channel = request.accept().await?;

            let request = {
                let mut requests = channel.requests();

                loop {
                    let request = requests.try_next().await?.expect("Session has been closed");

                    tracing::info!("Received channel request: {:?}", request.cx());

                    if matches!(
                        request.cx(),
                        ChannelRequestContext::Shell
                            | ChannelRequestContext::Exec { .. }
                            | ChannelRequestContext::Pty { .. }
                    ) {
                        break request;
                    }

                    request.accept().await?;
                }
            };

            let (mut reader, writer) = (channel.as_reader(), &mut channel.as_writer());
            request.accept().await?;

            for frame in FRAMES.iter().cycle() {
                let mut read = [0u8; 1];

                futures::select_biased! {
                    _ = tokio::time::sleep(DELAY).fuse() => {
                        writer.write_all(CLEAR.as_bytes()).await?;
                        writer.write_all(frame.as_bytes()).await?;
                        writer.flush().await?;
                    }
                    len = reader.read(&mut read).fuse() => {
                        if matches!(len, Ok(len) if len == 0 || read[0] == b'q') {
                            break;
                        }
                    }
                }
            }
            channel.eof().await?;

            Ok(())
        })
        .await
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    let keys = vec![
        ssh_key::private::PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519)
            .expect("Cannot generate private keys"),
    ];
    let listener = TcpListener::bind(args.address).await?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let keys = keys.clone();

        task::spawn(
            session(stream, keys)
                .inspect_err(|err| tracing::error!("Session ended with an error: {err:?}")),
        );
    }
}
