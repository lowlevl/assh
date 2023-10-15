use std::net::SocketAddr;

use async_std::{net::TcpListener, stream::StreamExt, task::JoinHandle};
use ssh_packet::trans::ServiceAccept;

use assh::{
    session::{server::Server, Session},
    Message, Result,
};

pub async fn server() -> Result<(SocketAddr, JoinHandle<Result<Message>>)> {
    let socket = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = socket.local_addr()?;

    let handle = async_std::task::spawn_local(async move {
        let stream = socket.incoming().next().await.unwrap()?;

        let side = Server {
            keys: vec![ssh_key::PrivateKey::random(
                &mut rand::thread_rng(),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap()],
            ..Default::default()
        };
        let mut session = Session::new(stream, side).await?;

        let request = match session.recv().await? {
            Message::ServiceRequest(request) => request,
            other => panic!("Unexpected message: {:?}", other),
        };

        session
            .send(&ServiceAccept {
                service_name: request.service_name,
            })
            .await?;

        session.recv().await
    });

    Ok((addr, handle))
}
