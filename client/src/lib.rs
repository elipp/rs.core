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

pub unsafe trait AsByteSlice: Sized + AnyBitPattern {
    fn as_bytes<'b>(&'b self) -> &'b [u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

#[repr(packed)]
#[derive(AnyBitPattern, Debug, Default, Clone, Copy)]
pub struct AuthResponse {
    pub opcode: u8,
    pub u1: u8,
    pub u2: u8,
    pub B: [u8; 32],
    pub u3: u8,
    pub g: u8,
    pub u4: u8,
    pub N: [u8; 32],
    pub salt: [u8; 32],
    pub unk1: [u8; 16],
    pub securityFlags: u8,
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
