use core::str;

use crypto::common::typenum::{UInt, UTerm};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rc4::{
    cipher::InvalidLength,
    consts::{B0, B1},
};
use sha1::{Digest, Sha1};

use rand::Rng;
use tokio::{io::AsyncReadExt, net::TcpStream};
use zerocopy::byteorder::network_endian;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

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
#[derive(Debug, FromZeroes, FromBytes, AsBytes)]
pub struct PktHeader {
    opcode: network_endian::U16,
    length: u16,
}

#[derive(Debug)]
pub enum ProtocolError {
    BadMagic,
    BadWowVersion,
    BadWowBuild,
    Error(String),
    Utf8Error,
    UnsupportedOsArch,
    AuthenticationError(String),
}

pub trait ZerocopyTraits: FromZeroes + FromBytes + AsBytes + Unaligned + Sized + 'static {}

const H: usize = size_of::<PktHeader>();

pub trait WowRawPacket: ZerocopyTraits {
    const S: usize = size_of::<Self>();

    #[allow(async_fn_in_trait)]
    async fn read_as_rawpacket<'b>(
        socket: &mut TcpStream,
        buf: &'b mut [u8],
    ) -> Result<Option<&'b Self>, ProtocolError> {
        socket
            .read_exact(&mut buf[..Self::S])
            .await
            .map_err(|e| ProtocolError::Error(format!("{e:?}")))?;

        Ok(Self::ref_from(&buf[..Self::S]))
    }
}

pub trait WowPacket: ZerocopyTraits {
    const S: usize = size_of::<Self>();

    #[allow(async_fn_in_trait)]
    async fn read_as_wowprotopacket<'b>(
        socket: &mut TcpStream,
        buf: &'b mut [u8],
    ) -> Result<(Option<&'b Self>, &'b [u8]), ProtocolError> {
        socket
            .read_exact(&mut buf[..H])
            .await
            .map_err(|e| ProtocolError::Error(format!("{e:?}")))?;
        if let Some(header) = PktHeader::read_from(&buf[..H]) {
            socket
                .read_exact(&mut buf[H..H + header.length as usize])
                .await
                .expect("failed to read data from socket");

            let content =
                &buf[size_of_val(&header)..(size_of_val(&header) + header.length as usize)];

            Ok((Self::ref_from(&content[..Self::S]), &content[Self::S..]))
        } else {
            Err(ProtocolError::Error(format!("bad header")))
        }
    }
}

#[repr(packed)]
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes, Unaligned)]
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

#[derive(Debug)]
pub enum ClientOs {
    Windows,
    Mac,
}

#[derive(Debug)]
pub enum ClientArch {
    X86,
    Ppc,
}

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
    pub fn get_client_language(&self) -> Result<String, ProtocolError> {
        Ok(str::from_utf8(&self.client_info_reversed[8..])
            .map_err(|_| ProtocolError::Utf8Error)?
            .chars()
            .rev()
            .collect())
    }

    // const CLIENTINFO: &[u8] = b"68x\0niW\0SUne";

    pub fn get_client_os_platform(&self) -> Result<(ClientOs, ClientArch), ProtocolError> {
        match (
            &self.client_info_reversed[4..7],
            &self.client_info_reversed[..3],
        ) {
            (b"niW", b"68x") => Ok((ClientOs::Windows, ClientArch::X86)),
            _ => Err(ProtocolError::UnsupportedOsArch),
        }
    }
}

impl ZerocopyTraits for AuthChallenge {}
impl WowPacket for AuthChallenge {}

#[repr(packed)]
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes, Unaligned)]
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

impl ZerocopyTraits for AuthResponse {}
impl WowPacket for AuthResponse {}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
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

#[repr(packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct AuthServerProof {
    pub cmd: u8,
    pub error: u8,
    pub M2: [u8; 20],
    pub accountFlags: u32,
    pub surveyId: u32,
    pub unkFlags: u16,
}

impl ZerocopyTraits for AuthServerProof {}
impl WowRawPacket for AuthServerProof {}

impl AuthServerProof {
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
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct AuthClientProof {
    pub cmd: u8,
    pub A: [u8; 32],
    pub M1: [u8; 20],
    pub crc: [u8; 20],
    pub nkeys: u8,
    pub security_flags: u8,
}

impl ZerocopyTraits for AuthClientProof {}
impl WowRawPacket for AuthClientProof {}

// /*static*/ std::array<uint8, 1> const SRP6::g = { 7 };
// /*static*/ std::array<uint8, 32> const SRP6::N = HexStrToByteArray<32>("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", true);
// /*static*/ BigNumber const SRP6::_g(SRP6::g);
// /*static*/ BigNumber const SRP6::_N(N);

#[allow(non_upper_case_globals)]
pub mod srp6 {
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::sync::LazyLock;

    pub const g: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_bytes_be(&[0x7]));
    pub const N: LazyLock<BigUint> = LazyLock::new(|| {
        BigUint::from_str_radix(
            "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
            16,
        )
        .unwrap()
    });
}

impl AuthClientProof {
    // static Verifier CalculateVerifier(std::string const& username, std::string const& password, Salt const& salt);
    // static EphemeralKey _B(BigNumber const& b, BigNumber const& v) { return ((_g.ModExp(b, _N) + (v * 3)) % N).ToByteArray<EPHEMERAL_KEY_LENGTH>(); }

    fn authenticate(&self, account: &Account) -> Result<(), ProtocolError> {
        let one = BigUint::from(1u32);
        let iA = BigUint::from_bytes_le(&self.A);
        if iA.modpow(&one, &*srp6::N) == BigUint::ZERO {
            return Err(ProtocolError::AuthenticationError(format!("bad iA {iA}")));
        }

        Ok(())
    }
}
