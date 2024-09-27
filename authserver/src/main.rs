use bytemuck::AnyBitPattern;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use client::AuthLogonProof;
use core::str;
use std::env;
use std::error::Error;

#[repr(C)]
#[derive(Debug)]
struct PktHeader {
    opcode: u16,
    length: u16,
}

#[repr(packed)]
#[derive(AnyBitPattern, Clone, Copy, Debug)]
struct AuthChallenge {
    wow: [u8; 4],
    version: [u8; 3],
    build: u16,
    client_info_reversed: [u8; 12],
    timezone: u32, // le
    ip: u32,       // le
    username_len: u8,
}

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
            let mut buf = vec![0; 1024];

            const H: usize = size_of::<PktHeader>();
            const S: usize = size_of::<AuthChallenge>();

            socket.read_exact(&mut buf[..H]).await.expect("challenge");
            let header = PktHeader {
                opcode: u16::from_be_bytes(buf[..2].try_into().unwrap()),
                length: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            };

            loop {
                socket
                    .read_exact(&mut buf[H..H + header.length as usize])
                    .await
                    .expect("failed to read data from socket");

                let content =
                    &buf[size_of_val(&header)..(size_of_val(&header) + header.length as usize)];

                let challenge: &AuthChallenge = bytemuck::from_bytes(&content[..S]);

                dbg!(&header, &challenge);

                let username =
                    match str::from_utf8(&content[S..S + challenge.username_len as usize]) {
                        Ok(username) => username,
                        Err(_) => {
                            drop(socket);
                            break;
                        }
                    };

                println!("username {username} logging in");

                assert_eq!(&challenge.wow, b"WoW\0");
                assert_eq!(&challenge.version, &[3, 3, 5]);
                assert_eq!(challenge.build.to_le(), 12340u16);

                // dbg!(challenge);
            }
        });
    }
}
