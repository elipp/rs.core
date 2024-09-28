use bytemuck::{AnyBitPattern, NoUninit};
use crypto::common::typenum::{UInt, UTerm};
use hmac::{Hmac, Mac};
use rc4::{
    cipher::InvalidLength,
    consts::{B0, B1},
};
use sha1::{Digest, Sha1};

const SHA_DIGEST_LENGTH: usize = 20;

pub fn vec_to_zero_padded_array<const N: usize>(vec: &[u8]) -> [u8; N] {
    assert!(vec.len() <= N);

    let mut array = [0u8; N];
    let offset = N.saturating_sub(vec.len());

    for (i, &item) in vec.iter().enumerate() {
        array[i + offset] = item;
    }

    array
}

pub fn sha1_hash<D: AsRef<[u8]>>(data: D) -> [u8; SHA_DIGEST_LENGTH] {
    let mut sha1 = Sha1::new();
    sha1.update(data);
    let hash = sha1.finalize();
    vec_to_zero_padded_array(&hash)
}

pub fn sha1_hmac(key: &[u8], data: &[u8]) -> Result<[u8; SHA_DIGEST_LENGTH], InvalidLength> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(key)?;
    hmac.update(data);
    let encrypt_digest = hmac.finalize();
    Ok(vec_to_zero_padded_array(&encrypt_digest.into_bytes()))
}

pub fn sha1_hash_iter<D: Iterator<Item = u8>>(data: D) -> Vec<u8> {
    let mut sha1 = Sha1::new();
    sha1.update(data.collect::<Vec<_>>());
    sha1.finalize().to_vec()
}

// DAYUUM xD
pub type WowRc4 = rc4::cipher::StreamCipherCoreWrapper<
    rc4::Rc4Core<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B1>, B0>, B0>>,
>;

pub const WOW_ENCRYPTION_KEY: &[u8] = &[
    0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE,
];

pub const WOW_DECRYPTION_KEY: &[u8] = &[
    0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57,
];

// looks like TBC probably uses a separate encryption scheme for auth
const _TBC_KEY_SEED: &[u8] = &[
    0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2, 0xAA,
];

#[repr(C)]
#[derive(Debug)]
pub struct PktHeader {
    opcode: u16,
    length: u16,
}

pub unsafe trait AsByteSlice: Sized + AnyBitPattern {
    fn as_bytes<'b>(&'b self) -> &'b [u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    BadMagic,
    BadWowVersion,
    BadWowBuild,
    Error(String),
}

const H: usize = size_of::<PktHeader>();

pub trait WowRawPacket: AsByteSlice {
    const S: usize = size_of::<Self>();

    async fn read_as_rawpacket<'b>(
        socket: &mut TcpStream,
        buf: &'b mut [u8],
    ) -> Result<&'b Self, ProtocolError> {
        socket
            .read_exact(&mut buf[..H])
            .await
            .map_err(|e| ProtocolError::Error(format!("{e:?}")))?;

        Ok(bytemuck::from_bytes(&buf[..Self::S]))
    }
}

pub trait WowPacket: AsByteSlice {
    const S: usize = size_of::<Self>();

    async fn read_as_wowprotopacket<'b>(
        socket: &mut TcpStream,
        buf: &'b mut [u8],
    ) -> Result<(&'b Self, &'b [u8]), ProtocolError> {
        socket
            .read_exact(&mut buf[..H])
            .await
            .map_err(|e| ProtocolError::Error(format!("{e:?}")))?;
        let header = PktHeader {
            opcode: u16::from_be_bytes(buf[..2].try_into().unwrap()),
            length: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
        };
        socket
            .read_exact(&mut buf[H..H + header.length as usize])
            .await
            .expect("failed to read data from socket");

        let content = &buf[size_of_val(&header)..(size_of_val(&header) + header.length as usize)];

        Ok((
            bytemuck::from_bytes(&content[..Self::S]),
            &content[Self::S..],
        ))
    }
}

#[repr(packed)]
#[derive(AnyBitPattern, Clone, Copy, Debug)]
pub struct AuthChallenge {
    wow: [u8; 4],
    version: [u8; 3],
    build: u16,
    client_info_reversed: [u8; 12],
    timezone: u32, // le
    ip: u32,       // le
    pub username_len: u8,
}

const WOTLK_BUILD: u16 = 12340;

impl AuthChallenge {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if &self.wow != b"WoW\0" {
            return Err(ProtocolError::BadMagic);
        }
        if &self.version != &[3, 3, 5] {
            return Err(ProtocolError::BadWowVersion);
        }
        if self.build.to_le() != 12340u16 {
            return Err(ProtocolError::BadWowBuild);
        }
        Ok(())
    }
}

unsafe impl AsByteSlice for AuthChallenge {}
impl WowPacket for AuthChallenge {}

#[repr(packed)]
#[derive(AnyBitPattern, Debug, Default, Clone, Copy)]
pub struct AuthResponse {
    pub opcode: u8,
    pub u1: u8,
    pub u2: u8,
    pub B: [u8; 32],
    pub u3: u8,
    pub g: [u8; 1],
    pub u4: u8,
    pub N: [u8; 32],
    pub salt: [u8; 32],
    pub unk1: [u8; 16],
    pub securityFlags: u8,
}

impl WowPacket for AuthResponse {}

use rand::Rng;
use tokio::{io::AsyncReadExt, net::TcpStream};

fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; N];
    rng.fill(&mut bytes);
    bytes
}

impl AuthResponse {
    pub fn new() -> Self {
        Self {
            opcode: commands::AUTH_LOGON_CHALLENGE,
            u1: 0x0,
            u2: 0x0,
            B: generate_random_bytes(),
            u3: 0x0,
            g: generate_random_bytes(),
            u4: 0x0,
            N: generate_random_bytes(),
            salt: generate_random_bytes(),
            unk1: generate_random_bytes(),
            securityFlags: 0x0,
        }
    }
}

unsafe impl AsByteSlice for AuthResponse {}

#[repr(packed)]
#[derive(Debug, AnyBitPattern, Clone, Copy)]
pub struct AuthLogonProof {
    pub cmd: u8,
    pub error: u8,
    pub M2: [u8; 20],
    pub accountFlags: u32,
    pub surveyId: u32,
    pub unkFlags: u16,
}

unsafe impl AsByteSlice for AuthLogonProof {}
impl WowRawPacket for AuthLogonProof {}

impl AuthLogonProof {
    pub fn validate() -> Result<(), ProtocolError> {
        Ok(())
    }
}

pub mod commands {
    pub const AUTH_LOGON_CHALLENGE: u8 = 0x0;
    pub const AUTH_LOGON_PROOF: u8 = 0x1;
    pub const CMD_REALM_LIST: u8 = 0x10;
}

pub type SessionKey = [u8; 40];

#[repr(packed)]
#[derive(Debug, AnyBitPattern, Clone, Copy)]
pub struct Proof {
    pub cmd: u8,
    pub A: [u8; 32],
    pub M1: [u8; 20],
    pub crc: [u8; 20],
    pub nkeys: u8,
    pub security_flags: u8,
}

unsafe impl AsByteSlice for Proof {}
