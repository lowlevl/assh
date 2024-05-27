use assh::{
    session::{self, client::Client, server::Server, Session, Side},
    Result,
};
use assh_auth::{handler, request};
use async_compat::CompatExt;
use futures::{AsyncBufRead, AsyncWrite};
use tokio::io::BufStream;

mod cookie {
    use std::sync::{atomic::AtomicBool, Arc};

    use super::*;

    #[derive(Debug, Default, Clone)]
    pub struct Cookie {
        flag: Arc<AtomicBool>,
    }

    impl Cookie {
        pub fn is_flagged(&self) -> bool {
            self.flag.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl assh::service::Request for Cookie {
        const SERVICE_NAME: &'static str = "ssh-connection";

        async fn proceed(
            &mut self,
            _session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin, impl Side>,
        ) -> Result<()> {
            self.flag.store(true, std::sync::atomic::Ordering::Relaxed);

            Ok(())
        }
    }
}

#[tokio::test]
async fn test() -> Result<(), Box<dyn std::error::Error>> {
    let duplex = tokio::io::duplex(ssh_packet::PACKET_MAX_SIZE * 16);

    let (mut server, mut client) = tokio::try_join!(
        session::Session::new(BufStream::new(duplex.0).compat(), Server::default()),
        session::Session::new(BufStream::new(duplex.1).compat(), Client::default()),
    )?;

    let cookie = cookie::Cookie::default();

    tokio::try_join!(
        assh::service::handle(&mut server, handler::Auth::new()),
        assh::service::request(&mut client, request::Auth::new("foobar", cookie.clone())),
    )?;

    assert!(cookie.is_flagged(), "Authentication did not succeed");

    Ok(())
}
