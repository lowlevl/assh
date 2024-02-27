use std::net::SocketAddr;

use async_std::{net::TcpListener, stream::StreamExt};
use futures::io::BufReader;

use assh::{
    session::{server::Server, Session},
    Result,
};
use ssh_packet::{
    connect::ChannelOpenConfirmation,
    trans::{Ignore, ServiceAccept},
    userauth::AuthSuccess,
    Message,
};

pub async fn server() -> Result<(SocketAddr, impl futures::Future<Output = Result<Message>>)> {
    let socket = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = socket.local_addr()?;

    let handle = async_std::task::spawn_local(async move {
        let stream = BufReader::new(socket.incoming().next().await.unwrap()?);

        let server = Server {
            keys: vec![ssh_key::PrivateKey::random(
                &mut rand::thread_rng(),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap()],
            ..Default::default()
        };
        let mut session = Session::new(stream, server).await?;

        // Trigger rekeying, since the threshold set is 1K.
        session
            .send(&Ignore {
                data: vec![0; 8192].into(),
            })
            .await?;

        let request = match session.recv().await? {
            Message::ServiceRequest(request) => request,
            other => panic!("Unexpected message: {:?}", other),
        };

        session
            .send(&ServiceAccept {
                service_name: request.service_name,
            })
            .await?;

        if let Message::AuthRequest { .. } = session.recv().await? {
            session.send(&AuthSuccess).await?;
        }

        if let Message::ChannelOpen(open) = session.recv().await? {
            session
                .send(&ChannelOpenConfirmation {
                    recipient_channel: open.sender_channel,
                    sender_channel: 0,
                    initial_window_size: open.initial_window_size,
                    maximum_packet_size: open.maximum_packet_size,
                })
                .await?;
        }

        session.recv().await
    });

    Ok((addr, handle))
}
