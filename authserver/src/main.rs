use auth::AuthResult;
use authserver::{new_auth_response, Account};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use tokio_postgres::NoTls;

use deadpool_postgres::{GenericClient, ManagerConfig, RecyclingMethod, Runtime};

use client::{
    commands, generate_random_bytes, AuthChallenge, AuthChallengeWithoutUsername, AuthClientProof,
    AuthResponse, AuthServerProof, ProtocolError, WowProtoPacket, WowRawPacket,
};
use core::str;
use std::env;
use std::error::Error;
use zerocopy::IntoBytes;

pub mod auth;

#[derive(Debug)]
pub enum AuthError {
    Error(String),
    DbError(tokio_postgres::Error),
}

impl From<tokio_postgres::Error> for AuthError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::DbError(e)
    }
}

impl From<AuthError> for ProtocolError {
    fn from(e: AuthError) -> Self {
        Self::Error(format!("{e:?}"))
    }
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
    cfg.host = Some(String::from("127.0.0.1"));
    cfg.user = Some(String::from("auth"));
    cfg.password = Some(String::from("asd"));
    cfg.dbname = Some("auth".to_string());
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap();

    loop {
        let (mut socket, _) = listener.accept().await?;
        let pool_clone = pool.clone();

        tokio::spawn(async move {
            let res = async move {
                // TODO: length bounds checking etc., since we're using user-provided length inputs
                let mut buf = vec![0; 1024];
                let ip = socket
                    .peer_addr()
                    .map_err(|e| AuthError::Error(format!("couldn't get peer addr: {e:?}")))?;

                let challenge = AuthChallenge::read_from_socket(&mut socket, &mut buf).await?;
                let username = match str::from_utf8(&challenge.username) {
                    Ok(username) => username.to_owned(),
                    Err(_) => {
                        return Err(ProtocolError::Error(format!("bad username")));
                    }
                };

                challenge.validate()?;

                let connection = pool_clone
                    .get()
                    .await
                    .map_err(|e| ProtocolError::DbError(format!("Pool error: {e:?}")))?;

                if let Some(account) = connection
                    .query_opt("SELECT * FROM account WHERE username=$1", &[&username])
                    .await
                    .map_err(|e| AuthError::DbError(e))?
                {
                    let account: Account = account.try_into()?;

                    println!(
                        "username {username} logging in from {ip:?} {} {:?}",
                        challenge.get_client_language()?,
                        challenge.get_client_os_platform()?
                    );

                    let response = new_auth_response(&account.salt, &account.verifier);
                    socket
                        .write_all(response.as_bytes())
                        .await
                        .expect("write authresponse failed");

                    let (proof, _) =
                        AuthClientProof::read_as_rawpacket(&mut socket, &mut buf).await?;
                    eprintln!("got client proof {proof:?}");
                    proof.verify(&account.salt, &account.verifier, &username)?;

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
                } else {
                    eprintln!("couldn't find user {username} from db");
                    todo!("write unknown account packet to socket and exit")
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                eprintln!("server error: {e:?}");
            }
        });
    }
}
