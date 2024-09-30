use auth::AuthResult;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use tokio_postgres::NoTls;

use deadpool_postgres::{ManagerConfig, RecyclingMethod, Runtime};

use client::{
    commands, generate_random_bytes, AuthChallenge, AuthClientProof, AuthResponse, AuthServerProof,
    ProtocolError, WowPacket, WowRawPacket,
};
use core::str;
use std::env;
use std::error::Error;
use zerocopy::AsBytes;

mod auth;

#[derive(Debug)]
pub enum AuthError {
    Error(String),
}

pub type PgPool = deadpool_postgres::Pool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:3724".to_string());

    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    let mut cfg = deadpool_postgres::Config::new();
    cfg.dbname = Some("auth".to_string());
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap();

    loop {
        // Asynchronously wait for an inbound socket.
        let (mut socket, _) = listener.accept().await?;
        let pool_clone = pool.clone();

        tokio::spawn(async move {
            // TODO: length bounds checking etc., since we're using user-provided length inputs
            let mut buf = vec![0; 1024];
            let ip = socket
                .peer_addr()
                .map_err(|e| ProtocolError::Error(format!("couldn't get peer addr: {e:?}")))?;

            if let (Some(challenge), after) =
                AuthChallenge::read_as_wowprotopacket(&mut socket, &mut buf).await?
            {
                let username = match str::from_utf8(&after[..challenge.username_len as usize]) {
                    Ok(username) => username,
                    Err(_) => {
                        return Err(ProtocolError::Error(format!("bad username")));
                    }
                };

                challenge.validate()?;
                println!(
                    "username {username} logging in from {ip:?} {} {:?}",
                    challenge.get_client_language()?,
                    challenge.get_client_os_platform()?
                );

                let response = AuthResponse::new();
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write authresponse failed");

                if let Some(proof) =
                    AuthClientProof::read_as_rawpacket(&mut socket, &mut buf).await?
                {
                    println!("{proof:?}");
                    let server_proof = AuthServerProof {
                        cmd: commands::AUTH_LOGON_PROOF,
                        error: AuthResult::Success as u8,
                        M2: generate_random_bytes(),
                        accountFlags: 0x0,
                        surveyId: 0x0,
                        unkFlags: 0x0,
                    };
                    socket
                        .write_all(server_proof.as_bytes())
                        .await
                        .map_err(|e| {
                            ProtocolError::Error(format!("writing AuthServerProof failed: {e:?}"))
                        })?;
                }
            }

            Ok(())
        });
    }
}
