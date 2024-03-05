use assh::session::{server::Server, Session};
use assh_auth::{
    server::{Auth, Response},
    Method,
};
use ssh_packet::userauth;

use async_std::{
    net::{TcpListener, TcpStream},
    task,
};
use clap::Parser;
use color_eyre::eyre;
use futures::{
    io::{BufReader, BufWriter},
    TryFutureExt,
};

/// An `assh` server example.
#[derive(Debug, Parser)]
pub struct Args {
    /// The port to bind with the listener on `127.0.0.1`.
    #[arg(short, long)]
    port: u16,
}

fn process(stream: TcpStream) -> impl futures::Future<Output = eyre::Result<()>> {
    let keys = vec![ssh_key::private::PrivateKey::random(
        &mut rand::thread_rng(),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap()];

    async move {
        let stream = BufReader::new(BufWriter::new(stream));
        let mut session = Session::new(
            stream,
            Server {
                keys,
                ..Default::default()
            },
        )
        .await?
        .add_layer(Auth::new(
            Some("Hi there :)\r\n"),
            Method::Password | Method::Publickey,
            |username, method| {
                tracing::info!("Authentication attempt for `{username}` with {method:?}");

                match method {
                    userauth::Method::Publickey { .. } => Response::Accept,
                    _ => Response::Reject,
                }
            },
        ));

        tracing::info!("Connected to `{}`", session.peer_id());

        loop {
            let message: ssh_packet::Message = session.recv().await?;

            tracing::info!("Incoming message: {message:?}");
        }
    }
}

#[async_std::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    let listener = TcpListener::bind(("127.0.0.1", args.port)).await?;

    loop {
        let (stream, addr) = listener.accept().await?;

        task::spawn(process(stream).inspect_err(move |err: &eyre::Error| {
            tracing::error!("Session errored with for {addr}: `{err:?}`")
        }));
    }
}
