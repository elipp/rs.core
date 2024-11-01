use num_bigint::BigUint;
use num_traits::Zero;
use rand::Rng;
use std::io::Cursor;
use std::mem::size_of;
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wow_proto::opcodes::{AuthOpcode, Opcode, ResponseCodes, OPCODE_NAME_MAP};
use wow_proto::utils::{interleave, partition, to_zero_padded_array_le};
use wow_proto::{
    sha1_digest, sha1_hmac, wotlk, AuthChallenge, AuthChallengeWithoutUsername, AuthClientProof,
    AuthProtoPacketHeader, AuthResponse, AuthServerProof, BigProtoPacketHeader, PacketHeader,
    PacketHeaderType, ProtoPacket, ProtoPacketHeader, ProtocolError, RealmAuthChallenge,
    RealmListResult, RecvPacket, RequestRealmlist, SendPacket, SessionKey, Sha1Digest,
    WotlkAuthResponse, WowRc4, WOW_DECRYPTION_KEY, WOW_ENCRYPTION_KEY, WOW_MAGIC,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use rc4::{Key, Rc4, StreamCipher};

pub mod warden;

// const REALMSERVER: &str = "logon.warmane.com:3724";
static REALMSERVER: LazyLock<String> = LazyLock::new(|| {
    std::env::var("AUTHSERVER_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3724".to_owned())
});

// const REALMSERVER: &str = "logon.stormforge.gg:3724";
const USERNAME: &str = "tlipp";
const PASSWORD: &str = "kuusysi69"; // lol these are case-insensitive apparently

const CLIENTINFO: [u8; 12] = *b"enUS\0Win\0x86";

const fn reverse_array<const N: usize>(arr: [u8; N]) -> [u8; N] {
    let mut reversed = [0u8; N];
    let mut i = 0;
    while i < N {
        reversed[i] = arr[(N - 1) - i];
        i += 1;
    }
    reversed
}

const CLIENTINFO_REVERSED: [u8; 12] = reverse_array(CLIENTINFO);

#[derive(Debug)]
enum WowCliError {
    RealmServerConnectionFailed,
    LoginFailed,
    UnexpectedResponse,
    UnexpectedResponseLength,
    IoError(std::io::Error),
    BufferTooSmall,
    RealmIsOffline,
    UnexpectedOpcode(u16),
    CryptoInvalidLength(crypto::common::InvalidLength),
    NetworkError,
    OtherError(String),
    ProtocolError(ProtocolError),
}

fn reversed<T: Clone>(arg: &[T]) -> Vec<T> {
    let mut r = arg.to_owned();
    r.reverse();
    r
}

type WowCliResult<T> = Result<T, WowCliError>;

fn new_auth_challenge<'b>(
    username: &str,
    buf: &'b mut [u8],
) -> &'b ProtoPacket<AuthProtoPacketHeader, AuthChallenge> {
    use std::io::Write;
    let header = AuthProtoPacketHeader::new(
        AuthOpcode::AUTH_LOGON_CHALLENGE as u16,
        size_of::<AuthChallengeWithoutUsername>() + username.as_bytes().len(),
    );

    let challenge: ProtoPacket<AuthProtoPacketHeader, AuthChallengeWithoutUsername> = ProtoPacket {
        header,
        body: AuthChallengeWithoutUsername {
            magic: WOW_MAGIC.to_owned(),
            version: wotlk::VERSION.to_owned(),
            build: wotlk::BUILD.to_owned(),
            client_info_reversed: CLIENTINFO_REVERSED.to_owned(),
            timezone: 0x78,
            ip: 0x6401A8C0,
            username_len: username
                .len()
                .try_into()
                .expect("username length to fit u16"),
        },
    };
    let offset = {
        let mut cursor = Cursor::new(&mut buf[..]);
        Write::write_all(&mut cursor, challenge.as_bytes()).unwrap();
        Write::write_all(&mut cursor, username.to_uppercase().as_bytes()).unwrap();
        cursor.position() as usize
    };
    ProtoPacket::<AuthProtoPacketHeader, AuthChallenge>::ref_from_bytes(&buf[..offset]).unwrap()
}

impl From<std::io::Error> for WowCliError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

#[allow(non_snake_case)]
fn calculate_proof_SRP(auth: &AuthResponse) -> WowCliResult<(AuthClientProof, SessionKey)> {
    let B = BigUint::from_bytes_le(&auth.b);
    let g = BigUint::from_bytes_le(&auth.g);
    let N = BigUint::from_bytes_le(&auth.n);

    let k = BigUint::from(3u32);

    let user_upper = USERNAME.to_uppercase();
    let xb = sha1_digest!(
        auth.salt,
        sha1_digest!(format!("{}:{}", user_upper, PASSWORD.to_uppercase()))
    );
    let x = BigUint::from_bytes_le(&xb);
    let one = BigUint::from(1u32);

    let mut a;
    let mut A;

    loop {
        let random_bytes = rand::thread_rng().gen::<[u8; 19]>();
        a = BigUint::from_bytes_le(&random_bytes);
        A = g.modpow(&a, &N);
        if !A.modpow(&one, &N).is_zero() {
            break;
        }
    }

    println!("{:X?}", A.to_bytes_be());

    let A_bytes = to_zero_padded_array_le::<32>(&A.to_bytes_le());
    let B_bytes = to_zero_padded_array_le::<32>(&B.to_bytes_le());

    let u = BigUint::from_bytes_le(&sha1_digest!(A_bytes, B_bytes));

    let S = (&B + (k * (&N - g.modpow(&x, &N))) % &N).modpow(&(&a + (&u * &x)), &N);
    let s_bytes = to_zero_padded_array_le::<32>(&S.to_bytes_le());
    let (s_even, s_odd) = partition(&s_bytes);
    let session_key = interleave(&sha1_digest!(s_even), &sha1_digest!(s_odd))?;
    let Nhash = sha1_digest!(auth.n);
    let ghash = sha1_digest!(auth.g);

    let gNhash: Vec<u8> = ghash.into_iter().zip(Nhash).map(|(g, n)| g ^ n).collect();

    Ok((
        AuthClientProof {
            cmd: AuthOpcode::AUTH_LOGON_PROOF as u8,
            a: A_bytes,
            m1: sha1_digest!(
                gNhash,
                sha1_digest!(user_upper),
                auth.salt,
                A_bytes,
                B_bytes,
                session_key
            ),
            crc: [0; 20],
            nkeys: 0,
            security_flags: 0,
        },
        session_key[..]
            .try_into()
            .map_err(|_| WowCliError::OtherError("session key".to_owned()))?,
    ))
}

#[allow(dead_code)]
#[derive(Debug)]
struct Realm {
    r#type: u8,
    lock: u8,
    flags: u8,
    name: String,
    address: String,
    poplevel: f32,
    num_chars: u8,
    timezone: u8,
    _unk1: u8,
}

impl Realm {
    fn online(&self) -> bool {
        self.flags & 0x2 == 0
    }
}

fn split_on_null_byte(data: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = data.iter().position(|&b| b == 0) {
        // Split at the position of the null byte
        let (before_null, after_null) = data.split_at(pos);
        // `after_null` starts at the null byte, so skip it by slicing 1 byte further
        (before_null, &after_null[1..])
    } else {
        // If no null byte found, return the whole slice and an empty slice
        (data, &[])
    }
}

async fn request_realmlist<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> WowCliResult<Vec<Realm>> {
    #[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
    #[repr(C, packed)]
    struct RealmFirstPart {
        r#type: u8,
        lock: u8,
        flags: u8,
    }

    #[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
    #[repr(C, packed)]
    struct RealmLastPart {
        poplevel: f32,
        num_chars: u8,
        timezone: u8,
        _unk1: u8,
    }

    let mut buf = vec![0u8; 1024 * 16];
    let request = RequestRealmlist::default();
    request.send(stream).await?;

    let realmlist = RealmListResult::recv(stream, &mut buf).await?;

    let mut realms = Vec::new();
    let mut current_body = &realmlist.body[..];
    for _ in 0..realmlist.num_realms {
        let (first, rest) = RealmFirstPart::ref_from_prefix(current_body).unwrap();
        let (name, rest) = split_on_null_byte(rest);
        let (address, rest) = split_on_null_byte(rest);
        let (last, rest) = RealmLastPart::ref_from_prefix(rest).unwrap();
        realms.push(Realm {
            r#type: first.r#type,
            lock: first.lock,
            flags: first.flags,
            name: String::from_utf8_lossy(name).to_string(),
            address: String::from_utf8_lossy(address).to_string(),
            poplevel: last.poplevel,
            num_chars: last.num_chars,
            timezone: last.timezone,
            _unk1: last._unk1,
        });
        current_body = rest;
    }
    Ok(realms)
}

impl From<crypto::common::InvalidLength> for WowCliError {
    fn from(err: crypto::common::InvalidLength) -> Self {
        Self::CryptoInvalidLength(err)
    }
}

fn into_wowrc4<const D: usize>(key: &[u8]) -> WowRc4 {
    use rc4::{consts::*, KeyInit};
    let mut d_zeros = vec![0u8; D];
    let mut rc4 = Rc4::new(Key::<U20>::from_slice(key));
    rc4.apply_keystream(&mut d_zeros);
    rc4
}

fn init_crypto(session_key: &SessionKey) -> WowCliResult<(WowRc4, WowRc4)> {
    const BYTES_TO_DROP: usize = 1024;
    Ok((
        into_wowrc4::<BYTES_TO_DROP>(&sha1_hmac(WOW_ENCRYPTION_KEY, session_key)?),
        into_wowrc4::<BYTES_TO_DROP>(&sha1_hmac(WOW_DECRYPTION_KEY, session_key)?),
    ))
}

#[derive(Debug)]
struct ServerPacketHeader {
    opcode: u16,
    header_length: usize,
    content_length: usize,
}

impl std::fmt::Display for ServerPacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ServerPacketHeader {{ opcode: {} (0x{:X}), packet_length: {} }}",
            (*OPCODE_NAME_MAP)
                .get(&self.opcode)
                .unwrap_or(&"UNKNOWN_OPCODE"),
            self.opcode,
            self.content_length
        )
    }
}

// pub enum Packet {
//     SmsgWardenData(WardenData),
// }

pub async fn read_one_encrypted<R>(
    read: &mut R,
    buf: &mut [u8],
    decrypt: &mut WowRc4,
) -> Result<(), ProtocolError>
where
    R: AsyncReadExt + Unpin,
{
    read.read_exact(&mut buf[..1])
        .await
        .map_err(|e| ProtocolError::NetworkError(format!("{e:?}")))?;
    decrypt.apply_keystream(&mut buf[..1]);

    let (opcode, body): (Opcode, &[u8]) = if (buf[0] & 0x80) > 0 {
        println!("have big packet");
        read.read_exact(&mut buf[1..5]).await.unwrap();
        decrypt.apply_keystream(&mut buf[1..5]);
        let header =
            PacketHeaderType::BigPacket(BigProtoPacketHeader::read_from_bytes(&buf[..5]).unwrap());
        read.read_exact(&mut buf[5..5 + header.packet_length()])
            .await
            .unwrap();
        (
            header.opcode().try_into()?,
            &buf[5..5 + header.packet_length()],
        )
    } else {
        read.read_exact(&mut buf[1..4]).await.unwrap();
        decrypt.apply_keystream(&mut buf[1..4]);
        let header =
            PacketHeaderType::Packet(ProtoPacketHeader::read_from_bytes(&buf[..4]).unwrap());
        read.read_exact(&mut buf[4..4 + header.packet_length()])
            .await
            .unwrap();
        (
            header.opcode().try_into()?,
            &buf[4..4 + header.packet_length()],
        )
    };

    if let Some(opcode_name) = OPCODE_NAME_MAP.get(&(opcode as u16)) {
        eprintln!("Packet: {}, len: {}", opcode_name, body.len());
    } else {
        eprintln!("Unnamed opcode {:x}?!", opcode as u16);
    }

    match opcode {
        Opcode::SMSG_AUTH_RESPONSE => match body {
            [first, rest @ ..] => match (*first).try_into()? {
                ResponseCodes::AUTH_OK => {
                    println!("Realm auth ok! ({rest:?})");
                }
                ResponseCodes::AUTH_REJECT | ResponseCodes::AUTH_FAILED => {
                    return Err(ProtocolError::AuthenticationError(format!(
                        "Authserver auth was ok, but worldserver rejected"
                    )))
                }
                b => todo!("{opcode:?} {b:?}"),
            },
            r => {
                eprintln!("server responded with {r:x?}");
            }
        },
        Opcode::SMSG_WARDEN_DATA => eprintln!("SMSG_WARDEN_DATA"),
        o => todo!("{o:?}"),
    }

    Ok(())
}

impl From<ProtocolError> for WowCliError {
    fn from(e: ProtocolError) -> Self {
        Self::ProtocolError(e)
    }
}

#[tokio::main]
async fn main() -> WowCliResult<()> {
    let mut buf = vec![0; 16 * 1024];
    let (realms, session_key): (Vec<Realm>, _) = {
        let mut stream = tokio::net::TcpStream::connect(&*REALMSERVER).await?;
        let challenge = new_auth_challenge(USERNAME, &mut buf);
        challenge.send(&mut stream).await?;

        let auth_response = AuthResponse::recv(&mut stream, &mut buf)
            .await
            .map_err(|e| WowCliError::LoginFailed)?;

        println!("got authresponse {:X?}", auth_response);
        if auth_response.opcode != AuthOpcode::AUTH_LOGON_CHALLENGE as u8
            || auth_response.u1 != 0x0
            || auth_response.u2 != 0x0
        {
            return Err(WowCliError::UnexpectedResponse);
        }

        let (proof, session_key) = calculate_proof_SRP(auth_response)?;
        proof.send(&mut stream).await?;
        println!("sent client proof {proof:?}");
        let server_proof = AuthServerProof::recv(&mut stream, &mut buf).await?;

        println!("got server proof {server_proof:?}");
        if server_proof.cmd == (AuthOpcode::AUTH_LOGON_PROOF as u8) && server_proof.error == 0x0 {
            println!("login at {} as {} successful!", &*REALMSERVER, USERNAME);
            (request_realmlist(&mut stream).await?, session_key)
        } else {
            return Err(WowCliError::LoginFailed);
        }
    };

    dbg!(&realms);

    if let Some(realm) = realms.iter().find(|r| r.name == "AzerothCore") {
        if !realm.online() {
            println!("realm {} is offline, not connecting!", realm.name);
            return Err(WowCliError::RealmIsOffline);
        }
        let mut stream = tokio::net::TcpStream::connect(&realm.address).await?;
        let realm_auth_challenge =
            ProtoPacket::<ProtoPacketHeader, RealmAuthChallenge>::recv(&mut stream, &mut buf)
                .await?;

        let challenge = realm_auth_challenge.body.clone();

        let auth_session =
            WotlkAuthResponse::new(&mut buf, USERNAME, 1, challenge.seed, &session_key)?;

        println!("{}", auth_session.header);
        auth_session.send(&mut stream).await?;

        let (mut encrypt, mut decrypt) = init_crypto(&session_key)?;
        loop {
            let packet = read_one_encrypted(&mut stream, &mut buf, &mut decrypt).await?;
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(())
}
