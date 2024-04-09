use assh::session::{server::Server, Session};
use assh_auth::{
    server::{password, publickey, Auth},
    Method,
};
use assh_connect::{channel, Connect};

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
        let session = Session::new(
            stream,
            Server {
                keys,
                ..Default::default()
            },
        )
        .await?
        .add_layer(
            Auth::new(Method::Password | Method::Publickey)
                .banner("Hi there !\r\n")
                .password(|_, _, new: Option<String>| {
                    if let Some(new) = new {
                        if new == "password1" {
                            password::Response::Accept
                        } else {
                            password::Response::PasswordExpired {
                                prompt: "[!] The only authorized new password is `password1`."
                                    .into(),
                            }
                        }
                    } else {
                        password::Response::PasswordExpired {
                            prompt: "[!] Password has expired for this user.".into(),
                        }
                    }
                })
                .publickey(|_, _| publickey::Response::Accept),
        );

        tracing::info!("Connected to `{}`", session.peer_id());

        Connect::new(session)
            .start(|_ctx, channel| {
                task::spawn::<_, eyre::Result<()>>(async move {
                    let response = channel
                        .on_request(|_ctx| channel::RequestResponse::Success)
                        .await?;

                    if response == channel::RequestResponse::Success {
                        futures::io::copy(channel.as_reader(), &mut channel.as_writer()).await?;

                        panic!("I/O closed");
                    } else {
                        panic!("channel closed");
                    }
                });

                true
            })
            .await?;

        Ok(())
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
