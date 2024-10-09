use client::{
    commands::{self, CMD_REALM_LIST},
    interleave, partition, sha1_hash, sha1_hash_iter, sha1_hmac, to_zero_padded_array_le,
    AuthChallenge, AuthChallengeWithoutUsername, AuthClientProof, AuthResponse, AuthServerProof,
    PktHeader, ProtoPacket, ProtocolError, RealmAuthChallenge, RealmListResult, RecvPacket,
    SendPacket, SessionKey, WowProtoPacket, WowRawPacket, WowRc4, WOTLK_BUILD, WOTLK_VERSION,
    WOW_DECRYPTION_KEY, WOW_ENCRYPTION_KEY, WOW_MAGIC,
};
use num_bigint::BigUint;
use num_traits::Zero;
use opcodes::Opcode;
use rand::Rng;
use std::mem::size_of;
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use rc4::{Key, Rc4, StreamCipher};

use crate::opcodes::OPCODE_NAME_MAP;

pub mod opcodes;
pub mod warden;

// const REALMSERVER: &str = "logon.warmane.com:3724";
static REALMSERVER: LazyLock<String> = LazyLock::new(|| {
    std::env::var("AUTHSERVER_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3724".to_owned())
});

// const REALMSERVER: &str = "logon.stormforge.gg:3724";
const USERNAME: &str = "tlipp";
const PASSWORD: &str = "kuusysi69"; // lol these are case-insensitive apparently

const CLIENTINFO: [u8; 12] = *b"enUS\0Win\0x86";
const CLIENTINFO_REVERSED: [u8; 12] = *b"68x\0niW\0SUne";

const BUILD: u16 = 12340;
const VERSION: [u8; 3] = [3, 3, 5];

// const VERSION: &[u8] = &[2, 4, 3];
// const BUILD: u16 = 8606;

// const CLIENTINFO: &[u8; 12] = b"enUS\0OSX\0x86";

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

fn new_auth_challenge(username: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    let header = PktHeader::new(
        opcodes::AuthOpcode::AUTH_LOGON_CHALLENGE as u16,
        size_of::<AuthChallengeWithoutUsername>() + username.as_bytes().len(),
    );

    dbg!(header);

    let challenge: ProtoPacket<AuthChallengeWithoutUsername> = ProtoPacket {
        header,
        body: AuthChallengeWithoutUsername {
            magic: WOW_MAGIC.to_owned(),
            version: WOTLK_VERSION.to_owned(),
            build: WOTLK_BUILD.to_owned(),
            client_info_reversed: CLIENTINFO_REVERSED.to_owned(),
            timezone: 0x78,
            ip: 0x6401A8C0,
            username_len: username
                .len()
                .try_into()
                .expect("username length to fit u16"),
        },
    };
    buf.extend_from_slice(challenge.as_bytes());
    buf.extend_from_slice(username.to_uppercase().as_bytes());
    buf
}

impl From<std::io::Error> for WowCliError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

#[allow(non_snake_case)]
fn calculate_proof_SRP(auth: &AuthResponse) -> WowCliResult<(AuthClientProof, SessionKey)> {
    let B = BigUint::from_bytes_le(&auth.B);
    let g = BigUint::from_bytes_le(&auth.g);
    let N = BigUint::from_bytes_le(&auth.N);

    let k = BigUint::from(3u32);

    let user_upper = USERNAME.to_uppercase();
    let xb = sha1_hash_iter(auth.salt.into_iter().chain(sha1_hash(
        format!("{}:{}", user_upper, PASSWORD.to_uppercase()).into_bytes(),
    )));
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

    let u = BigUint::from_bytes_le(&sha1_hash_iter(
        A_bytes.iter().chain(B_bytes.iter()).copied(),
    ));

    let S = (&B + (k * (&N - g.modpow(&x, &N))) % &N).modpow(&(&a + (&u * &x)), &N);
    let s_bytes = to_zero_padded_array_le::<32>(&S.to_bytes_le());
    let (s_even, s_odd) = partition(&s_bytes);
    let session_key = interleave(&sha1_hash(s_even), &sha1_hash(s_odd))?;
    let Nhash = sha1_hash(auth.N);
    let ghash = sha1_hash(auth.g);

    let gNhash: Vec<u8> = ghash.into_iter().zip(Nhash).map(|(g, n)| g ^ n).collect();

    let mut m1 = Vec::new();
    m1.extend(gNhash);
    m1.extend(sha1_hash(user_upper));
    m1.extend(auth.salt);
    m1.extend(&A_bytes);
    m1.extend(&B_bytes);
    m1.extend(&session_key);

    Ok((
        AuthClientProof {
            cmd: commands::AUTH_LOGON_PROOF,
            A: A_bytes,
            M1: sha1_hash(m1),
            crc: [0; 20],
            nkeys: 0,
            security_flags: 0,
        },
        session_key[..]
            .try_into()
            .map_err(|_| WowCliError::OtherError("session key".to_owned()))?,
    ))
}

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

#[derive(IntoBytes, Immutable)]
#[repr(C, packed)]
struct RequestRealmlist {
    cmd: u8,
    unknown: [u8; 4],
}

impl Default for RequestRealmlist {
    fn default() -> Self {
        Self {
            cmd: CMD_REALM_LIST,
            unknown: [0; 4],
        }
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

    let realmlist = ProtoPacket::<RealmListResult>::recv(stream, &mut buf)
        .await
        .unwrap();

    let mut realms = Vec::new();
    let mut current_body = &realmlist.body.body[..];
    for _ in 0..realmlist.body.num_realms {
        let (first, rest) = RealmFirstPart::ref_from_prefix(current_body).unwrap();
        let (name, rest) = split_on_null_byte(rest);
        let (address, rest) = split_on_null_byte(rest);
        let (last, rest) = RealmLastPart::ref_from_prefix(rest).unwrap();
        realms.push(Realm {
            name: String::from_utf8_lossy(name).to_string(),
            address: String::from_utf8_lossy(address).to_string(),
            r#type: first.r#type,
            lock: first.lock,
            flags: first.flags,
            poplevel: last.poplevel,
            num_chars: last.num_chars,
            timezone: last.timezone,
            _unk1: last._unk1,
        });
        current_body = rest;
    }
    Ok(realms)
}

#[derive(Debug)]
struct ClientPacketHeader {
    bytes: [u8; 6],
}

impl ClientPacketHeader {
    fn new(cmd: Opcode, length: usize) -> Self {
        let mut bytes = [0u8; 6];
        bytes[..2].copy_from_slice(&((length + 4) as u16).to_be_bytes());
        bytes[2..].copy_from_slice(&(cmd as u32).to_le_bytes());
        Self { bytes }
    }
}

fn print_as_c_array(title: &str, bytes: &[u8]) {
    println!("{title}:");
    for (i, b) in bytes.iter().enumerate() {
        print!("0x{:X}, ", b);
        if i % 10 == 9 {
            println!("");
        }
    }
    println!("");
}

fn get_auth_session(
    username: &str,
    session_key: &SessionKey,
    challenge: &RealmAuthChallenge,
) -> WowCliResult<Vec<u8>> {
    let username_upper = username.to_uppercase();
    let mut res = Vec::new();
    let header = ClientPacketHeader::new(opcodes::Opcode::CMSG_AUTH_SESSION, 0x3D + username.len());
    res.extend(header.bytes);
    res.extend((BUILD as u32).to_le_bytes());
    res.extend([0; 4]);
    res.extend(username_upper.as_bytes());
    res.push(0); // null terminator
    res.extend([0; 4]);
    let our_seed = rand::thread_rng().gen::<u32>();
    res.extend(our_seed.to_le_bytes());
    res.extend([0; 8]);
    res.extend(1u32.to_le_bytes()); // realmID
    res.extend([0; 8]);

    let mut hashbuf = Vec::new();
    hashbuf.extend(username_upper.as_bytes());
    hashbuf.extend([0; 4]);
    hashbuf.extend(our_seed.to_le_bytes());
    hashbuf.extend(challenge.seed.to_le_bytes());
    hashbuf.extend(session_key);
    let hashbuf_sha = sha1_hash(&hashbuf);

    res.extend(hashbuf_sha);
    res.extend([0; 4]);

    Ok(res)
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

fn decrypt_header(buf: &mut [u8], decrypt: &mut WowRc4) -> ServerPacketHeader {
    decrypt.apply_keystream(&mut buf[..1]);
    let header_length = if (buf[0] & 0x80) > 0 {
        println!("have big packet");
        5
    } else {
        4
    };
    decrypt.apply_keystream(&mut buf[1..header_length]);
    let mut content_length = [0u8; size_of::<u32>()];
    let mut opcode = [0u8; size_of::<u16>()];
    if header_length == 5 {
        content_length[1..].copy_from_slice(&[buf[0] & 0x7f, buf[1], buf[2]]);
        opcode.copy_from_slice(&buf[3..5]);
    } else {
        content_length[2..].copy_from_slice(&buf[..2]);
        opcode.copy_from_slice(&buf[2..4]);
    }
    ServerPacketHeader {
        opcode: u16::from_le_bytes(opcode),
        header_length,
        content_length: u32::from_be_bytes(content_length) as usize,
    }
}

impl From<ProtocolError> for WowCliError {
    fn from(e: ProtocolError) -> Self {
        Self::ProtocolError(e)
    }
}

#[tokio::main]
async fn main() -> WowCliResult<()> {
    let mut buf = vec![0; 1024];
    let (realms, session_key): (Vec<Realm>, _) = {
        let mut stream = tokio::net::TcpStream::connect(&*REALMSERVER).await?;
        let challenge = new_auth_challenge(USERNAME);

        let packet = ProtoPacket::<AuthChallenge>::ref_from_bytes(&challenge).unwrap();
        packet.send(&mut stream).await?;

        let (auth_response, _) = AuthResponse::read_as_rawpacket(&mut stream, &mut buf)
            .await
            .map_err(|e| WowCliError::LoginFailed)?;

        println!("got authresponse {:X?}", auth_response);
        if auth_response.opcode != commands::AUTH_LOGON_CHALLENGE
            || auth_response.u1 != 0x0
            || auth_response.u2 != 0x0
        {
            return Err(WowCliError::UnexpectedResponse);
        }

        let (proof, session_key) = calculate_proof_SRP(auth_response)?;
        proof.send(&mut stream).await?;
        println!("sent client proof {proof:?}");
        let (server_proof, _) = AuthServerProof::read_as_rawpacket(&mut stream, &mut buf).await?;

        println!("got server proof {server_proof:?}");
        if server_proof.cmd == commands::AUTH_LOGON_PROOF && server_proof.error == 0x0 {
            println!("login at {} as {} successful!", &*REALMSERVER, USERNAME);
            (request_realmlist(&mut stream).await?, session_key)
        } else {
            return Err(WowCliError::LoginFailed);
        }
    };

    dbg!(&realms);

    if let Some(realm) = realms.iter().find(|r| r.name == "Netherwing") {
        if !realm.online() {
            println!("realm {} is offline, not connecting!", realm.name);
            return Err(WowCliError::RealmIsOffline);
        }
        let mut stream = tokio::net::TcpStream::connect(&realm.address).await?;
        let realm_auth_challenge =
            RealmAuthChallenge::read_as_wowprotopacket(&mut stream, &mut buf)
                .await
                .map_err(|e| WowCliError::NetworkError)?;
        let auth_session = get_auth_session(USERNAME, &session_key, &realm_auth_challenge)?;
        stream.write_all(&auth_session).await?;
        let (mut encrypt, mut decrypt) = init_crypto(&session_key)?;
        let mut read_buf = [0; 4096];
        loop {
            // TODO: fix
            // let bytes = stream.read(&mut read_buf)?;
            // let mut processed: usize = 0;
            // while processed < bytes {
            //     let packet_header = decrypt_header(&mut read_buf[processed..], &mut decrypt);
            //     println!("{packet_header} (read {}/{} bytes)", processed, bytes);
            //     processed += packet_header.content_length + packet_header.header_length - 2;
            // }
            // std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(())
}
