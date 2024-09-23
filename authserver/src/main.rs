use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use std::env;
use std::error::Error;
use std::mem::MaybeUninit;

#[repr(C)]
#[derive(Debug)]
struct PktHeader {
    opcode: u16,
    length: u16,
}

#[repr(C, packed)]
#[derive(Debug)]
struct AuthChallenge {
    wow: [u8; 4],
    version: [u8; 3],
    build: u16,
    client_info_reversed: [u8; 12],
    timezone: u32, // le
    ip: u32,       // le
    username_len: u8,
    username: [u8; 256],
}

#[derive(Debug)]
pub enum AuthError {
    Error(String),
}

unsafe fn read_as<R: std::io::Read, T: Sized>(
    stream: &mut R,
    max_len: Option<usize>,
) -> Result<T, AuthError> {
    let mut read_buf = vec![0; size_of::<T>()];
    stream
        .read_exact(&mut read_buf)
        .map_err(|e| AuthError::Error(format!("{e:?}")))?;
    let mut res = MaybeUninit::<T>::uninit();

    std::ptr::copy_nonoverlapping(
        read_buf.as_ptr(),
        res.as_mut_ptr() as *mut u8,
        max_len.unwrap_or(size_of::<T>()),
    );
    Ok(res.assume_init())
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
            let mut header_buf = [0u8; 4];
            let mut buf = vec![0; 1024];

            let n = socket.read_exact(&mut header_buf).await.expect("challenge");
            if n == 0 {
                panic!("read of {n}");
            }
            let header = PktHeader {
                opcode: u16::from_be_bytes(header_buf[..2].try_into().unwrap()),
                length: u16::from_le_bytes(header_buf[2..4].try_into().unwrap()),
            };

            loop {
                let n = socket
                    .read_exact(&mut buf[..header.length as usize])
                    .await
                    .expect("failed to read data from socket");

                dbg!(&buf[..header.length as usize]);

                // I copied this code from Stack Overflow
                // without understanding why this case is safe.
                let (head, body, _tail) = unsafe { buf.align_to::<AuthChallenge>() };
                assert!(head.is_empty(), "Data was not aligned");
                let challenge = &body[0];

                println!("{:?}", challenge);

                dbg!(&header);

                // let challenge = unsafe {
                //     read_as::<_, AuthChallenge>(
                //         &mut std::io::Cursor::new(&buf),
                //         Some((header.length - 30) as usize),
                //     )
                // }
                // .unwrap();

                // if n == 0 {
                //     panic!("expected to read {header:?}");
                // }

                assert_eq!(&challenge.wow, b"WoW\0");
                assert_eq!(&challenge.version, &[3, 3, 5]);
                assert_eq!(challenge.build.to_le(), 12340u16);

                // dbg!(challenge);
            }
        });
    }
}
