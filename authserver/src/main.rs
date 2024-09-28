use bytemuck::AnyBitPattern;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use client::{
    commands, AsByteSlice, AuthChallenge, AuthLogonProof, AuthResponse, ProtocolError, WowPacket,
};
use core::str;
use std::env;
use std::error::Error;

#[derive(Debug)]
pub enum AuthError {
    Error(String),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:3724".to_string());

    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        // Asynchronously wait for an inbound socket.
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            // TODO: length bounds checking etc., since we're using user-provided length inputs
            let mut buf = vec![0; 1024];

            let (challenge, after) =
                AuthChallenge::read_as_wowprotopacket(&mut socket, &mut buf).await?;

            let username = match str::from_utf8(&after[..challenge.username_len as usize]) {
                Ok(username) => username,
                Err(_) => {
                    return Err(ProtocolError::Error(format!("bad username")));
                }
            };

            println!("username {username} logging in");
            challenge.validate()?;

            let response = AuthResponse::new();
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write authresponse failed");

            let (proof, _) = AuthLogonProof::read_as_wowprotopacket(&mut socket, &mut buf).await?;

            dbg!(proof);

            Ok(())
        });
    }
}
