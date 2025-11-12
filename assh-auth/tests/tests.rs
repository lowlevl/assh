use assh::{
    Result,
    side::{client::Client, server::Server},
};
use assh_auth::{handler, request};
use async_compat::CompatExt;
use tokio::io::BufStream;

mod cookie;

#[tokio::test]
async fn basic_none() -> Result<(), Box<dyn std::error::Error>> {
    let duplex = tokio::io::duplex(ssh_packet::Packet::MAX_SIZE * 16);

    let cookie0 = cookie::Cookie::default();
    let cookie1 = cookie::Cookie::default();

    tokio::try_join!(
        async {
            let server = Server {
                keys: vec![
                    ssh_key::private::PrivateKey::random(
                        &mut rand::thread_rng(),
                        ssh_key::Algorithm::Ed25519,
                    )
                    .unwrap(),
                ],
                ..Default::default()
            };
            let server = assh::Session::new(BufStream::new(duplex.0).compat(), server).await?;

            server
                .handle(
                    handler::Auth::new(cookie0.clone()).none(|_| handler::none::Response::Accept),
                )
                .await
        },
        async {
            let client = Client::default();
            let client = assh::Session::new(BufStream::new(duplex.1).compat(), client).await?;

            client
                .request(request::Auth::new("user", cookie1.clone()))
                .await
        },
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
