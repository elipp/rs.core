use client::{
    commands, sha1_hash, sha1_hash_iter, sha1_hmac, vec_to_zero_padded_array, AuthClientProof,
    AuthServerProof, AuthResponse, SessionKey, WowRc4, WOW_DECRYPTION_KEY, WOW_ENCRYPTION_KEY,
};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::Rng;
use std::io::prelude::*;
use std::mem::{size_of, MaybeUninit};
use std::net::TcpStream;
use zerocopy::AsBytes;

use rc4::{Key, Rc4, StreamCipher};

use crate::opcodes::OPCODE_NAME_MAP;

pub mod opcodes;
pub mod warden;

// const REALMSERVER: &str = "logon.warmane.com:3724";
const REALMSERVER: &str = "127.0.0.1:3724";
// const REALMSERVER: &str = "logon.stormforge.gg:3724";
const USERNAME: &str = "tlipp";
const PASSWORD: &str = "kuusysi69"; // lol these are case-insensitive apparently

const CLIENTINFO: &[u8] = b"enUS\0Win\0x86";

const BUILD: u16 = 12340;
const VERSION: &[u8] = &[3, 3, 5];

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
    OtherError(String),
}

fn reversed<T: Clone>(arg: &[T]) -> Vec<T> {
    let mut r = arg.to_owned();
    r.reverse();
    r
}

type WowCliResult<T> = Result<T, WowCliError>;

fn get_auth_challenge(username: &str) -> WowCliResult<Vec<u8>> {
    let mut buf = Vec::<u8>::new();
    buf.push(0x00);
    buf.push(0x06);
    buf.extend(((username.len() + 30) as u16).to_le_bytes());
    buf.extend(b"WoW\0".as_slice());
    buf.extend(VERSION);
    buf.extend(BUILD.to_le_bytes());
    buf.extend(reversed(CLIENTINFO));
    buf.extend((0x78 as u32).to_le_bytes()); // timezone bias
    buf.extend((0x6401A8C0 as u32).to_le_bytes()); // ip, 192.168.1.100
    buf.push(username.len() as u8);
    buf.extend(username.to_uppercase().into_bytes());
    println!("{buf:?}");
    Ok(buf)
}

impl From<std::io::Error> for WowCliError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

fn interleave<T: Copy>(a: &[T], b: &[T]) -> WowCliResult<Vec<T>> {
    if a.len() != b.len() {
        return Err(WowCliError::OtherError(
            "interleave: a.len() != b.len()".to_owned(),
        ));
    }
    let mut res = Vec::with_capacity(a.len() * 2);
    for i in 0..a.len() {
        res.push(a[i]);
        res.push(b[i]);
    }
    Ok(res)
}

fn partition<T: Copy>(s: &[T]) -> (Vec<T>, Vec<T>) {
    assert_eq!(s.len() % 2, 0);
    let half_len = s.len() / 2;
    let mut a = Vec::with_capacity(half_len);
    let mut b = Vec::with_capacity(half_len);
    for i in 0..half_len {
        a.push(s[2 * i]);
        b.push(s[2 * i + 1]);
    }
    (a, b)
}

fn calculate_proof_SRP(auth: AuthResponse) -> WowCliResult<(AuthClientProof, SessionKey)> {
    let B = BigUint::from_bytes_le(&auth.B);
    let g = BigUint::from_bytes_le(&auth.g);
    let N = BigUint::from_bytes_le(&auth.N);
    let s = BigUint::from_bytes_le(&auth.salt);

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
    let A_bytes = vec_to_zero_padded_array::<32>(&A.to_bytes_le());
    let B_bytes = vec_to_zero_padded_array::<32>(&B.to_bytes_le());

    let u = BigUint::from_bytes_le(&sha1_hash_iter(
        A_bytes.iter().chain(B_bytes.iter()).copied(),
    ));

    let S = (&B + (k * (&N - g.modpow(&x, &N))) % &N).modpow(&(&a + (&u * &x)), &N);
    let s_bytes = vec_to_zero_padded_array::<32>(&S.to_bytes_le());
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

unsafe fn read_as<R: std::io::Read, T: Sized>(stream: &mut R) -> WowCliResult<T> {
    let mut read_buf = vec![0; size_of::<T>()];
    stream.read_exact(&mut read_buf)?;
    let mut res = MaybeUninit::<T>::uninit();
    std::ptr::copy_nonoverlapping(
        read_buf.as_ptr(),
        res.as_mut_ptr() as *mut u8,
        size_of::<T>(),
    );
    Ok(res.assume_init())
}

fn read_byte<R: std::io::Read>(stream: &mut R) -> WowCliResult<u8> {
    let mut res = [0u8; 1];
    stream.read_exact(&mut res)?;
    Ok(res[0])
}

#[derive(Debug)]
#[repr(packed)]
struct RealmListResult {
    cmd: u8,
    packet_size: u16,
    _unused: u32,
    num_realms: u16,
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

#[derive(Debug)]
#[repr(packed)]
struct RealmAuthChallenge {
    header: u16,
    opcode: u16,
    one: u32,
    seed: u32,
    seed1: [u8; 16],
    seed2: [u8; 16],
}

fn read_chunk<S: std::io::Read, const N: usize>(stream: &mut S) -> WowCliResult<Vec<u8>> {
    let mut res = [0u8; N];
    let bytes = stream.read(&mut res)?;
    if bytes >= N {
        // bug: could be exactly `bytes`...
        return Err(WowCliError::BufferTooSmall);
    }

    Ok(res[..bytes].to_vec())
}

fn read_until_null<R: Read>(reader: &mut R) -> WowCliResult<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0; 1]; // Read one byte at a time

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break, // End of input stream
            Ok(_) => {
                if buf[0] == 0 {
                    break; // Null byte found, stop reading
                }
                data.push(buf[0]);
            }
            Err(e) => return Err(WowCliError::IoError(e)),
        }
    }

    Ok(data)
}

fn request_realmlist<S: std::io::Read + std::io::Write>(
    stream: &mut S,
) -> WowCliResult<Vec<Realm>> {
    stream.write_all(&[commands::CMD_REALM_LIST, 0x0, 0x0, 0x0, 0x0])?;
    let realmlist: RealmListResult = unsafe { read_as(stream) }?;
    let rest_of_bytes = read_chunk::<_, 4096>(stream)?;
    let mut cursor = std::io::Cursor::new(rest_of_bytes);
    let mut realms = Vec::new();
    for _ in 0..realmlist.num_realms {
        unsafe {
            realms.push(Realm {
                r#type: read_as(&mut cursor)?,
                lock: read_as(&mut cursor)?,
                flags: read_as(&mut cursor)?,
                name: String::from_utf8_lossy(&read_until_null(&mut cursor)?).to_string(),
                address: String::from_utf8_lossy(&read_until_null(&mut cursor)?).to_string(),
                poplevel: read_as(&mut cursor)?,
                num_chars: read_as(&mut cursor)?,
                timezone: read_as(&mut cursor)?,
                _unk1: read_as(&mut cursor)?,
            });
        }
    }
    Ok(realms)
}

#[derive(Debug)]
struct ClientPacketHeader {
    bytes: [u8; 6],
}

impl ClientPacketHeader {
    fn new(cmd: u16, length: usize) -> Self {
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
    let header = ClientPacketHeader::new(opcodes::CMSG_AUTH_SESSION, 0x3D + username.len());
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
            OPCODE_NAME_MAP
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

fn main() -> WowCliResult<()> {
    let (realms, session_key) = {
        let mut stream = TcpStream::connect(REALMSERVER)?;
        let challenge = get_auth_challenge(USERNAME)?;
        stream.write_all(&challenge[..])?;
        let auth: AuthResponse = unsafe { read_as(&mut stream) }?;
        if auth.opcode != commands::AUTH_LOGON_CHALLENGE || auth.u1 != 0x0 || auth.u2 != 0x0 {
            return Err(WowCliError::UnexpectedResponse);
        }
        let (proof, session_key) = calculate_proof_SRP(auth)?;
        stream.write_all(proof.as_bytes())?;
        let server_proof: AuthServerProof = unsafe { read_as(&mut stream) }?;

        if server_proof.cmd == commands::AUTH_LOGON_PROOF && server_proof.error == 0x0 {
            println!("login at {} as {} successful!", REALMSERVER, USERNAME);
        } else {
            return Err(WowCliError::LoginFailed);
        }

        (request_realmlist(&mut stream)?, session_key)
    };

    dbg!(&realms);

    if let Some(realm) = realms.iter().find(|r| r.name == "Netherwing") {
        if !realm.online() {
            println!("realm {} is offline, not connecting!", realm.name);
            return Err(WowCliError::RealmIsOffline);
        }
        let mut stream = TcpStream::connect(&realm.address)?;
        let realm_auth_challenge: RealmAuthChallenge = unsafe { read_as(&mut stream) }?;
        if realm_auth_challenge.opcode != opcodes::SMSG_AUTH_CHALLENGE {
            return Err(WowCliError::UnexpectedOpcode(realm_auth_challenge.opcode));
        }
        let auth_session = get_auth_session(USERNAME, &session_key, &realm_auth_challenge)?;
        stream.write_all(&auth_session)?;
        let (mut encrypt, mut decrypt) = init_crypto(&session_key)?;
        let mut read_buf = [0; 4096];
        loop {
            let bytes = stream.read(&mut read_buf)?;
            let mut processed: usize = 0;
            while processed < bytes {
                let packet_header = decrypt_header(&mut read_buf[processed..], &mut decrypt);
                println!("{packet_header} (read {}/{} bytes)", processed, bytes);
                processed += packet_header.content_length + packet_header.header_length - 2;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(())
}
