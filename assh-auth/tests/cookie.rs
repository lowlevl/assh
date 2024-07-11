//! A dummy subservice to test for authentication success.

use assh::{side::Side, Pipe, Result, Session};

const SERVICE_NAME: &str = "dummy-service@assh.rs";

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
    const SERVICE_NAME: &'static str = SERVICE_NAME;

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

    const SERVICE_NAME: &'static str = SERVICE_NAME;

    async fn on_request<IO, S>(&mut self, _: Session<IO, S>) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        self.flag.store(true, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }
}
