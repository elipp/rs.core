use tokio::net::TcpListener;

use tokio_postgres::NoTls;

use deadpool_postgres::{GenericClient, ManagerConfig, RecyclingMethod, Runtime};

use wow_proto::{
    AuthChallenge, AuthClientProof, AuthProtoPacketHeader, AuthServerProof, ProtoPacket,
    ProtocolError, RecvPacket, SendPacket,
};

use core::str;
use std::env;
use std::error::Error;

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
        .unwrap_or_else(|| "0.0.0.0:8086".to_string());

    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(tracing::Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Listening on: {}", addr);

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
            let res: Result<(), ProtocolError> = async move {
                // TODO: length bounds checking etc., since we're using user-provided length inputs
                let mut buf = vec![0u8; 16 * 1024];
                let ip = socket
                    .peer_addr()
                    .map_err(|e| AuthError::Error(format!("couldn't get peer addr: {e:?}")))?;

                Ok(())
            }
            .await;
            if let Err(e) = res {
                tracing::error!("server error: {e:?}");
            } else {
            }
        });
    }
}
