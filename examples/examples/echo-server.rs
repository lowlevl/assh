use std::{net::SocketAddr, sync::Arc};

use assh::{side::server::Server, Session};
use assh_auth::handler::{none, Auth};
use assh_connect::{channel, connect::channel_open::Outcome};

use async_compat::CompatExt;
use clap::Parser;
use color_eyre::eyre;
use futures::{
    io::{BufReader, BufWriter},
    TryFutureExt, TryStreamExt,
};
use ssh_packet::connect;
use tokio::{net::TcpListener, task};

/// An `assh` server example, echoing back all sent data.
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

        task::spawn(
            async move {
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

                let connect = session
                    .handle(
                        Auth::new(assh_connect::Service)
                            .banner("Welcome, and get echo'd\r\n")
                            .none(|_| none::Response::Accept),
                    )
                    .await?;

                let connect = Arc::new(connect);

                task::spawn({
                    let connect = connect.clone();

                    async move {
                        connect
                            .global_requests()
                            .try_for_each(|request| async move {
                                Ok(tracing::warn!(
                                    "Received GlobalRequest from peer: {request:?}"
                                ))
                            })
                            .await
                            .expect("GlobalRequest handler has failed")
                    }
                });

                task::spawn({
                    let connect = connect.clone();

                    async move {
                        connect
                            .channel_opens()
                            .try_for_each(|request| async move {
                                Ok(tracing::warn!(
                                    "Received ChannelOpen from peer: {request:?}"
                                ))
                            })
                            .await
                            .expect("ChannelOpen handler has failed")
                    }
                });

                // connect
                //     .on_channel_open(|_, channel: channel::Channel| {
                //         task::spawn(
                //             async move {
                //                 channel
                //                     .requests()
                //                     .take_while(|request| {
                //                         futures::future::ready(matches!(
                //                             request.ctx(),
                //                             connect::ChannelRequestContext::Shell
                //                                 | connect::ChannelRequestContext::Exec { .. }
                //                                 | connect::ChannelRequestContext::Subsystem { .. }
                //                         ))
                //                     })
                //                     .for_each(|request| async {
                //                         request.accept().await;
                //                     })
                //                     .await;

                //                 futures::io::copy(
                //                     &mut channel.as_reader(),
                //                     &mut channel.as_writer(),
                //                 )
                //                 .await?;

                //                 Ok(channel.eof().await?)
                //             }
                //             .inspect_err(|err: &eyre::Error| {
                //                 tracing::error!("Channel closed with an error: {err:?}")
                //             }),
                //         );

                //         Outcome::Accept
                //     })
                //     .spin()
                //     .await?;

                Ok::<_, eyre::Error>(())
            }
            .inspect_err(|err| tracing::error!("Session ended with an error: {err:?}")),
        );
    }
}
