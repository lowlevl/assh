use assh::{
    session::{self, client::Client, server::Server, Session, Side},
    Result,
};
use assh_auth::{handler, request};
use async_compat::CompatExt;
use futures::{AsyncBufRead, AsyncWrite};
use tokio::io::BufStream;

mod cookie {
    const SERVICE_NAME: &str = "dummy-service@assh.rs";

    use std::{rc::Rc, sync::atomic::AtomicBool};

    use super::*;

    #[derive(Debug, Default, Clone)]
    pub struct Cookie {
        flag: Rc<AtomicBool>,
    }

    impl Cookie {
        pub fn is_flagged(&self) -> bool {
            self.flag.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl assh::service::Request for Cookie {
        const SERVICE_NAME: &'static str = SERVICE_NAME;

        async fn request<I, S>(&mut self, _: &mut Session<I, S>) -> Result<()>
        where
            I: AsyncBufRead + AsyncWrite + Unpin,
            S: Side,
        {
            self.flag.store(true, std::sync::atomic::Ordering::Relaxed);

            Ok(())
        }
    }

    impl assh::service::Handler for Cookie {
        const SERVICE_NAME: &'static str = SERVICE_NAME;

        async fn handle<I, S>(&mut self, _: &mut Session<I, S>) -> Result<()>
        where
            I: AsyncBufRead + AsyncWrite + Unpin,
            S: Side,
        {
            self.flag.store(true, std::sync::atomic::Ordering::Relaxed);

            Ok(())
        }
    }
}

#[tokio::test]
async fn test() -> Result<(), Box<dyn std::error::Error>> {
    let duplex = tokio::io::duplex(ssh_packet::PACKET_MAX_SIZE * 16);

    let server = Server {
        keys: vec![ssh_key::private::PrivateKey::random(
            &mut rand::thread_rng(),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap()],
        ..Server::default()
    };
    let client = Client::default();

    let (mut server, mut client) = tokio::try_join!(
        session::Session::new(BufStream::new(duplex.0).compat(), server),
        session::Session::new(BufStream::new(duplex.1).compat(), client),
    )?;

    let cookie0 = cookie::Cookie::default();
    let cookie1 = cookie::Cookie::default();

    tokio::try_join!(
        assh::service::handle(
            &mut server,
            handler::Auth::new(cookie0.clone()).none(|_| handler::none::Response::Accept)
        ),
        assh::service::request(&mut client, request::Auth::new("user", cookie1.clone())),
    )?;

    assert!(
        cookie0.is_flagged(),
        "Authentication handling did not succeed"
    );
    assert!(
        cookie1.is_flagged(),
        "Authentication request did not succeed"
    );

    Ok(())
}
