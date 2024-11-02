//! A dummy subservice to test for authentication success.

use assh::{side::Side, Pipe, Result, Session};
use ssh_packet::arch::{ascii, Ascii};

const SERVICE_NAME: Ascii<'_> = ascii!("dummy-service@assh.rs");

use std::{rc::Rc, sync::atomic::AtomicBool};

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
    const SERVICE_NAME: Ascii<'static> = SERVICE_NAME;

    type Err = assh::Error;
    type Ok<IO: Pipe, S: Side> = ();

    async fn on_accept<IO, S>(&mut self, _: Session<IO, S>) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        self.flag.store(true, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }
}

impl assh::service::Handler for Cookie {
    type Err = assh::Error;
    type Ok<IO: Pipe, S: Side> = ();

    const SERVICE_NAME: Ascii<'static> = SERVICE_NAME;

    async fn on_request<IO, S>(&mut self, _: Session<IO, S>) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        self.flag.store(true, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }
}
