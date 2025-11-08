use assh::{Pipe, Session, service, side::Side};
use ssh_packet::arch::{Ascii, ascii};

use super::Connect;

const SERVICE_NAME: Ascii<'static> = ascii!("ssh-connection");

/// An [`assh::service`] that yields a [`Connect`].
pub struct Service;

impl service::Handler for Service {
    type Err = assh::Error;
    type Ok<IO: Pipe, S: Side> = Connect<IO, S>;

    const SERVICE_NAME: Ascii<'static> = SERVICE_NAME;

    async fn on_request<IO, S>(
        &mut self,
        session: Session<IO, S>,
    ) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        Ok(Connect::new(session))
    }
}

impl service::Request for Service {
    type Err = assh::Error;
    type Ok<IO: Pipe, S: Side> = Connect<IO, S>;

    const SERVICE_NAME: Ascii<'static> = SERVICE_NAME;

    async fn on_accept<IO, S>(
        &mut self,
        session: Session<IO, S>,
    ) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        Ok(Connect::new(session))
    }
}
