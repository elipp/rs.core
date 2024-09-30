use core::str;

mod opcodes;

use crypto::common::typenum::{UInt, UTerm};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::Num;
use opcodes::{AuthOpcode, Opcode};
use rc4::{
    cipher::InvalidLength,
    consts::{B0, B1},
};
use sha1::{Digest, Sha1};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zerocopy::byteorder::network_endian;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

const SHA_DIGEST_LENGTH: usize = 20;

pub fn interleave<T: Copy>(a: &[T], b: &[T]) -> Result<Vec<T>, ProtocolError> {
    if a.len() != b.len() {
        return Err(ProtocolError::Error(
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

pub fn partition<T: Copy>(s: &[T]) -> (Vec<T>, Vec<T>) {
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

pub fn to_zero_padded_array<const N: usize>(vec: &[u8]) -> [u8; N] {
    assert!(vec.len() <= N);

    let mut array = [0u8; N];
    let offset = N.saturating_sub(vec.len());

    (&mut array[offset..]).copy_from_slice(&vec);

    array
}

pub fn sha1_hash<D: AsRef<[u8]>>(data: D) -> [u8; SHA_DIGEST_LENGTH] {
    let mut sha1 = Sha1::new();
    sha1.update(data);
    let hash = sha1.finalize();
    to_zero_padded_array(&hash)
}

pub fn sha1_hmac(key: &[u8], data: &[u8]) -> Result<[u8; SHA_DIGEST_LENGTH], InvalidLength> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(key)?;
    hmac.update(data);
    let encrypt_digest = hmac.finalize();
    Ok(to_zero_padded_array(&encrypt_digest.into_bytes()))
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
    DbError(String),
}

pub trait ZerocopyTraits: FromZeroes + FromBytes + AsBytes + Unaligned + Sized + 'static {}

const H: usize = size_of::<PktHeader>();

#[allow(async_fn_in_trait)]
pub trait WowRawPacket: ZerocopyTraits {
    const S: usize = size_of::<Self>();

    #[allow(async_fn_in_trait)]
    async fn read_as_rawpacket<'b, R: AsyncReadExt + Unpin>(
        read: &mut R,
        buf: &'b mut [u8],
    ) -> Result<(Option<&'b Self>, &'b [u8]), ProtocolError> {
        read.read_exact(&mut buf[..Self::S])
            .await
            .map_err(|e| ProtocolError::Error(format!("{e:?}")))?;

        Ok((Self::ref_from(&buf[..Self::S]), &buf[Self::S..]))
    }
}

#[allow(async_fn_in_trait)]
pub trait WowProtoPacket: ZerocopyTraits {
    const SIZE_WITHOUT_HEADER: usize = size_of::<Self>();
    const SIZE_WITH_HEADER: usize = size_of::<PktHeader>() + size_of::<Self>();
    const O: u16;

    async fn read_as_wowprotopacket<'b, R: AsyncReadExt + Unpin>(
        read: &mut R,
        buf: &'b mut [u8],
    ) -> Result<(Option<&'b Self>, &'b [u8]), ProtocolError> {
        read.read_exact(&mut buf[..H])
            .await
            .map_err(|e| ProtocolError::Error(format!("{e:?}")))?;
        if let Some(header) = PktHeader::read_from(&buf[..H]) {
            read.read_exact(&mut buf[H..H + header.length as usize])
                .await
                .expect("failed to read data from socket");

            let content =
                &buf[size_of_val(&header)..(size_of_val(&header) + header.length as usize)];

            let res = Self::ref_from(&content[..Self::SIZE_WITHOUT_HEADER]);
            // TODO garbage logic
            if res.is_some() && header.opcode.get() != Self::O as u16 {
                return Err(ProtocolError::Error(format!("Opcode doesn't match")));
            }
            Ok((res, &content[Self::SIZE_WITHOUT_HEADER..]))
        } else {
            Err(ProtocolError::Error(format!("bad header")))
        }
    }
    async fn write_as_wowprotopacket<'b, W: AsyncWriteExt + Unpin>(
        &self,
        length: u16,
        write: &mut W,
        tail: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        let header = PktHeader {
            opcode: (Self::O as u16).into(),
            length,
        };
        write
            .write_all(header.as_bytes())
            .await
            .map_err(|e| ProtocolError::Error(format!("header write failed")))?;
        write
            .write_all(self.as_bytes())
            .await
            .map_err(|e| ProtocolError::Error(format!("packet write failed")))?;

        if let Some(tail) = tail {
            write
                .write_all(tail)
                .await
                .map_err(|e| ProtocolError::Error(format!("packet write failed")))?;
        }
        Ok(())
    }
}

#[repr(packed)]
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct AuthChallenge {
    pub magic: [u8; 4],
    pub version: [u8; 3],
    pub build: u16,
    pub client_info_reversed: [u8; 12],
    pub timezone: u32, // le
    pub ip: u32,       // le
    pub username_len: u8,
}

pub const WOW_MAGIC: &[u8; 4] = b"WoW\0";
pub const WOTLK_BUILD: u16 = 12340;
pub const WOTLK_VERSION: &[u8; 3] = &[3, 3, 5];

#[derive(Debug)]
pub enum ClientOs {
    Windows,
    Mac,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ClientArch {
    x86,
    PPC,
}

impl AuthChallenge {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if &self.magic != WOW_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if &self.version != WOTLK_VERSION {
            return Err(ProtocolError::BadWowVersion);
        }
        if self.build.to_le() != WOTLK_BUILD {
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
            (b"niW", b"68x") => Ok((ClientOs::Windows, ClientArch::x86)),
            _ => Err(ProtocolError::UnsupportedOsArch),
        }
    }
}

impl ZerocopyTraits for AuthChallenge {}
impl WowProtoPacket for AuthChallenge {
    const O: u16 = AuthOpcode::AUTH_LOGON_CHALLENGE as u16;
}

pub type Salt = [u8; 32];
pub type Verifier = [u8; 32];

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
    pub salt: Salt,
    pub unk1: [u8; 16], // some versionchallenge apparently?
    pub securityFlags: u8,
}

impl ZerocopyTraits for AuthResponse {}
impl WowRawPacket for AuthResponse {}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; N];
    rng.fill(&mut bytes);
    bytes
}

pub fn generate_random_bytes_vec<const N: usize>() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::with_capacity(N);
    rng.fill(&mut bytes[..]);
    bytes
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
    use std::sync::LazyLock;

    pub const _g: u8 = 0x7;
    pub const g: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_bytes_be(&[_g]));

    pub const N_BYTES: [u8; 32] = [
        0x89, 0x4B, 0x64, 0x5E, 0x89, 0xE1, 0x53, 0x5B, 0xBD, 0xAD, 0x5B, 0x8B, 0x29, 0x06, 0x50,
        0x53, 0x08, 0x01, 0xB1, 0x8E, 0xBF, 0xBF, 0x5E, 0x8F, 0xAB, 0x3C, 0x82, 0x87, 0x2A, 0x3E,
        0x9B, 0xB7,
    ];

    pub const N: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_bytes_be(&N_BYTES));
}

impl AuthClientProof {
    // static Verifier CalculateVerifier(std::string const& username, std::string const& password, Salt const& salt);
    // static EphemeralKey _B(BigNumber const& b, BigNumber const& v) { return ((_g.ModExp(b, _N) + (v * 3)) % N).ToByteArray<EPHEMERAL_KEY_LENGTH>(); }

    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        auth_response: &AuthResponse,
        salt: &Salt,
        verifier: &Verifier,
        username_upper: &str,
    ) -> Result<SessionKey, ProtocolError> {
        let As = "1e707e2c2b994cbd8750f7e70232239b3a46c8d0f85c8cff163b8c403cd94b20";
        let Bs = "4a07f2766d971451a2b716fa69530d7d583f82edd23b116c7e34ca21c7a6ed3e";

        let _bs = "F590ADFDFB7BB0F1E1C754A6114B2492BD5F252DB023F770B8799322B16ADF35";

        let A = BigUint::from_str_radix(As, 16).unwrap();
        let Ab = A.to_bytes_be();
        let B = BigUint::from_str_radix(Bs, 16).unwrap();
        let Bb = B.to_bytes_be();

        let _b = BigUint::from_str_radix(_bs, 16).unwrap();

        let v = BigUint::from_bytes_le(verifier);

        let one = BigUint::from(1u32);
        if A.modpow(&one, &srp6::N) == BigUint::ZERO {
            return Err(ProtocolError::AuthenticationError(format!("bad A {A}")));
        }
        let uhash = sha1_hash_iter(Ab.iter().chain(Bb.iter()).copied());
        println!("uhash {:X?}", uhash);
        let u = BigUint::from_bytes_be(&uhash);

        let S = (&A * (v.modpow(&u, &srp6::N))).modpow(&_b, &srp6::N);
        println!("S_bytes_be: {:X?}", S.to_bytes_be());
        let S_bytes = to_zero_padded_array::<32>(&S.to_bytes_be());
        let (s_even, s_odd) = partition(&S_bytes);
        let session_key: SessionKey =
            to_zero_padded_array(&interleave(&sha1_hash(s_even), &sha1_hash(s_odd))?);

        println!("Ab: {:X?}", Ab);
        println!("Bb: {:X?}", Bb);
        println!("S: {:X?}", S_bytes);

        println!("u: {:X?}", u.to_bytes_le());
        println!("v: {:X?}", v.to_bytes_le());
        println!("salt: {:X?}", salt);
        println!("K: {:X?}", session_key);
        println!("N: {:X?}", auth_response.N);

        let Nhash = sha1_hash_iter(auth_response.N.iter().copied().rev());
        let ghash = sha1_hash(auth_response.g);

        let Ng_hash: Vec<u8> = Nhash
            .clone()
            .into_iter()
            .zip(ghash)
            .map(|(n, g)| n ^ g)
            .collect();

        println!(
            "Nhash: {:X?}\nghash: {:X?}\nNg_hash: {:X?}",
            Nhash, ghash, Ng_hash
        );

        // // NgHash = H(N) xor H(g)
        // SHA1::Digest const NHash = SHA1::GetDigestOf(N);
        // SHA1::Digest const gHash = SHA1::GetDigestOf(g);
        // SHA1::Digest NgHash;
        // std::transform(NHash.begin(), NHash.end(), gHash.begin(), NgHash.begin(), std::bit_xor<>());

        let _I = sha1_hash(username_upper.as_bytes());
        println!("_I: {:X?}", _I);

        let our_M = sha1_hash_iter(
            (Ng_hash
                .iter()
                .chain(_I.iter())
                .chain(salt.iter())
                .chain(A.to_bytes_le().iter())
                .chain(B.to_bytes_le().iter())
                .chain(session_key.iter()))
            .copied(),
        );
        if our_M == self.M1 {
            Ok(session_key)
        } else {
            Err(ProtocolError::AuthenticationError(format!(
                "wrong password probably"
            )))
        }
    }
}

#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, Unaligned)]
#[repr(packed)]
pub struct RealmAuthChallenge {
    pub one: u32,
    pub seed: u32,
    pub seed1: [u8; 16],
    pub seed2: [u8; 16],
}

impl ZerocopyTraits for RealmAuthChallenge {}
impl WowProtoPacket for RealmAuthChallenge {
    const O: u16 = opcodes::Opcode::SMSG_AUTH_CHALLENGE as u16;
}

#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, Unaligned)]
#[repr(packed)]
pub struct RealmListResult {
    pub cmd: u8,
    pub packet_size: u16,
    pub _unused: u32,
    pub num_realms: u16,
}

impl ZerocopyTraits for RealmListResult {}
impl WowProtoPacket for RealmListResult {
    const O: u16 = opcodes::Opcode::MSG_NULL_ACTION as u16;
}
