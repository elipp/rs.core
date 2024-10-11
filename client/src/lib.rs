use core::str;
use std::fmt::LowerHex;

mod opcodes;

use crypto::common::typenum::{UInt, UTerm};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use opcodes::AuthOpcode;
use rc4::{
    cipher::InvalidLength,
    consts::{B0, B1},
};
use sha1::{Digest, Sha1};

use rand::Rng;
use srp6::N_BYTES_LE;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zerocopy::{byteorder::network_endian, little_endian, Immutable, IntoBytes, KnownLayout};
use zerocopy::{FromBytes, FromZeros, Unaligned};

const SHA_DIGEST_LENGTH: usize = 20;

pub type Sha1Digest = [u8; SHA_DIGEST_LENGTH];

pub mod wotlk {
    pub const BUILD: u16 = 12340;
    pub const VERSION: [u8; 3] = [3, 3, 5];
}

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

pub fn to_zero_padded_array_le<const N: usize>(vec: &[u8]) -> [u8; N] {
    assert!(vec.len() <= N);

    let mut array = [0u8; N];
    let offset = N.saturating_sub(vec.len());

    (&mut array[offset..]).copy_from_slice(&vec);

    array
}

pub fn sha1_hash<D: AsRef<[u8]>>(data: D) -> Sha1Digest {
    let mut sha1 = Sha1::new();
    sha1.update(data);
    let hash = sha1.finalize();
    hash.as_slice()
        .try_into()
        .expect("sha1 digest length to be 20")
}

pub fn sha1_hmac(key: &[u8], data: &[u8]) -> Result<Sha1Digest, InvalidLength> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(key)?;
    hmac.update(data);
    let encrypt_digest = hmac.finalize();
    Ok(encrypt_digest
        .into_bytes()
        .as_slice()
        .try_into()
        .expect("sha1 hmac digest length to be 20"))
}

pub fn sha1_hash_iter<D: Iterator<Item = u8>>(data: D) -> Sha1Digest {
    let mut sha1 = Sha1::new();
    sha1.update(data.collect::<Vec<_>>());
    sha1.finalize()
        .as_slice()
        .try_into()
        .expect("sha1 digest length to be 20")
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

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct AuthProtoPacketHeader {
    opcode: network_endian::U16,
    length: u16,
}

impl AuthProtoPacketHeader {}

impl std::fmt::Display for ProtoPacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opcode = self.opcode();
        write!(
            f,
            "{} {{ opcode: 0x{:X}, length: {} }}",
            std::any::type_name_of_val(self),
            opcode,
            self.packet_length()
        )
    }
}

impl std::fmt::Display for AuthProtoPacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opcode = self.opcode();
        write!(
            f,
            "{} {{ opcode: 0x{:X}, length: {} }}",
            std::any::type_name_of_val(self),
            opcode,
            self.packet_length()
        )
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ProtoPacketHeader {
    length: network_endian::U16,
    opcode: u16,
}

pub type U24 = [u8; 3];

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct BigProtoPacketHeader {
    length: U24,
    opcode: u16,
}

fn transform_to_u32(u: &U24) -> u32 {
    let b0 = u[0] as u32;
    let b1 = u[1] as u32;
    let b2 = (u[2] & 0x7F) as u32;

    (b2 << 16) | (b1 << 8) | b0
}

fn reverse_from_u32(u: u32) -> U24 {
    let b0 = (u & 0xFF) as u8;
    let b1 = ((u >> 8) & 0xFF) as u8;
    let b2 = ((u >> 16) & 0x7F) as u8 | 0x80;

    [b0, b1, b2]
}

impl PacketHeader for BigProtoPacketHeader {
    fn packet_length(&self) -> usize {
        transform_to_u32(&self.length) as usize
    }

    fn opcode(&self) -> u16 {
        self.opcode
    }

    fn new(opcode: u16, length: usize) -> Self {
        Self {
            opcode,
            length: reverse_from_u32(length as u32),
        }
    }

    fn resize(&mut self, new_size: usize) {
        self.length = reverse_from_u32(new_size as u32)
    }
}

pub enum PacketHeaderType {
    Packet(ProtoPacketHeader),
    BigPacket(BigProtoPacketHeader),
}

impl PacketHeaderType {
    pub fn packet_length(&self) -> usize {
        match self {
            PacketHeaderType::Packet(p) => p.packet_length(),
            PacketHeaderType::BigPacket(p) => p.packet_length(),
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ClientPacketHeader {
    length: network_endian::U16,
    opcode: u32,
}

impl std::fmt::Display for ClientPacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opcode = self.opcode();
        write!(
            f,
            "{} {{ opcode: 0x{:X}, length: {} }}",
            std::any::type_name_of_val(self),
            opcode,
            self.packet_length()
        )
    }
}

impl PacketHeader for ClientPacketHeader {
    fn packet_length(&self) -> usize {
        self.length.into()
    }

    fn opcode(&self) -> u16 {
        self.opcode as u16
    }

    fn new(opcode: u16, length: usize) -> Self {
        Self {
            length: (length as u16).into(),
            opcode: opcode as u32,
        }
    }

    fn resize(&mut self, new_size: usize) {
        self.length = (new_size as u16).into();
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    BadMagic,
    BadWowVersion,
    BadWowBuild,
    Error(String),
    NetworkError(String),
    Utf8Error,
    UnsupportedOsArch,
    AuthenticationError(String),
    DbError(String),
    ZerocopyError(String),
    UnexpectedOpcode(u16, u16),
}

pub trait PacketHeader: Sized {
    fn packet_length(&self) -> usize;
    fn opcode(&self) -> u16;
    fn new(opcode: u16, length: usize) -> Self;
    fn resize(&mut self, new_size: usize);
}

impl PacketHeader for AuthProtoPacketHeader {
    fn packet_length(&self) -> usize {
        self.length as usize
    }
    fn opcode(&self) -> u16 {
        self.opcode.get()
    }

    fn new(opcode: u16, length: usize) -> Self {
        Self {
            opcode: (opcode as u16).into(),
            length: length as u16,
        }
    }

    fn resize(&mut self, new_size: usize) {
        self.length = new_size as u16;
    }
}

impl PacketHeader for ProtoPacketHeader {
    fn packet_length(&self) -> usize {
        self.length.get() as usize - size_of_val(&self.length)
    }

    fn opcode(&self) -> u16 {
        self.opcode
    }

    fn new(opcode: u16, length: usize) -> Self {
        Self {
            opcode,
            length: (length as u16).into(),
        }
    }

    fn resize(&mut self, new_size: usize) {
        self.length = (new_size as u16).into()
    }
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct ProtoPacket<H: Sized + PacketHeader, T: ?Sized> {
    pub header: H,
    pub body: T,
}

#[repr(C, packed)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Unaligned, Immutable)]
pub struct AuthChallengeWithoutUsername {
    pub magic: [u8; 4],
    pub version: [u8; 3],
    pub build: u16,
    pub client_info_reversed: [u8; 12],
    pub timezone: u32, // le
    pub ip: u32,       // le
    pub username_len: u8,
}

pub trait SendPacket {
    async fn send<W: AsyncWriteExt + Unpin>(&self, write: &mut W) -> Result<(), ProtocolError>;
}

pub trait RecvPacket: 'static {
    const H: usize;
    async fn recv<'b, R: AsyncReadExt + Unpin>(
        write: &mut R,
        buf: &'b mut [u8],
    ) -> Result<&'b Self, ProtocolError>;
}

impl<T> SendPacket for T
where
    T: IntoBytes + Immutable + ?Sized,
{
    async fn send<W: AsyncWriteExt + Unpin>(&self, write: &mut W) -> Result<(), ProtocolError> {
        // println!(
        //     "sending packet of {} bytes: {:?}",
        //     self.as_bytes().len(),
        //     self.as_bytes()
        // );
        write
            .write_all(self.as_bytes())
            .await
            .map_err(|e| ProtocolError::NetworkError(format!("{e:?}")))
    }
}

impl<Header, Payload> RecvPacket for ProtoPacket<Header, Payload>
where
    Header: FromBytes + KnownLayout + Immutable + Unaligned + Sized + PacketHeader + 'static,
    Payload: FromBytes + KnownLayout + Immutable + Unaligned + ?Sized + 'static,
{
    const H: usize = size_of::<Header>();
    async fn recv<'b, R: AsyncReadExt + Unpin>(
        read: &mut R,
        buf: &'b mut [u8],
    ) -> Result<&'b Self, ProtocolError> {
        read.read_exact(&mut buf[..Self::H])
            .await
            .map_err(|e| ProtocolError::Error(String::from("read()")))?;

        let header = Header::read_from_bytes(&buf[..Self::H])
            .map_err(|e| ProtocolError::ZerocopyError(format!("{e}")))?;

        read.read_exact(&mut buf[Self::H..Self::H + header.packet_length()])
            .await
            .map_err(|e| ProtocolError::Error(String::from("read() 2")))?;

        Ok(
            Self::ref_from_bytes(&buf[..Self::H + header.packet_length()])
                .map_err(|e| ProtocolError::ZerocopyError(format!("{e}")))?,
        )
    }
}

impl RecvPacket for RealmListResult {
    const H: usize = size_of::<RealmListHeader>();
    async fn recv<'b, R: AsyncReadExt + Unpin>(
        read: &mut R,
        buf: &'b mut [u8],
    ) -> Result<&'b Self, ProtocolError> {
        read.read_exact(&mut buf[..Self::H])
            .await
            .map_err(|e| ProtocolError::Error(String::from("read()")))?;

        let header = RealmListHeader::read_from_bytes(&buf[..Self::H])
            .map_err(|e| ProtocolError::ZerocopyError(format!("{e}")))?;

        if header.cmd != AuthOpcode::REALM_LIST as u8 {
            return Err(ProtocolError::UnexpectedOpcode(
                header.cmd as u16,
                AuthOpcode::REALM_LIST as u16,
            ));
        }

        read.read_exact(&mut buf[Self::H..header.packet_size as usize])
            .await
            .map_err(|e| ProtocolError::Error(String::from("read()")))?;

        Ok(
            Self::ref_from_bytes(&buf[..Self::H + header.packet_size as usize])
                .map_err(|e| ProtocolError::ZerocopyError(format!("{e}")))?,
        )
    }
}

trait FixedSizePacket:
    IntoBytes + FromBytes + KnownLayout + Immutable + Unaligned + Sized + 'static
{
}

impl<T> RecvPacket for T
where
    T: FixedSizePacket,
{
    const H: usize = size_of::<Self>();
    async fn recv<'b, R: AsyncReadExt + Unpin>(
        read: &mut R,
        buf: &'b mut [u8],
    ) -> Result<&'b Self, ProtocolError> {
        eprintln!("trying to read fixed packet of {} bytes", size_of::<Self>());
        read.read_exact(&mut buf[..Self::H])
            .await
            .map_err(|e| ProtocolError::Error(String::from("read()")))?;

        Ok(Self::ref_from_bytes(&buf[..size_of::<Self>()])
            .map_err(|e| ProtocolError::ZerocopyError(format!("{e}")))?)
    }
}

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, KnownLayout, Unaligned, Immutable)]
pub struct AuthChallenge {
    pub header: AuthChallengeWithoutUsername,
    pub username: [u8],
}

impl std::fmt::Display for AuthChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthChallenge {{ header: {:?}, username: {:?} }}",
            self.header,
            &self.username[..]
        )
    }
}

pub const WOW_MAGIC: &[u8; 4] = b"WoW\0";

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
        if &self.header.magic != WOW_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if &self.header.version != &wotlk::VERSION {
            return Err(ProtocolError::BadWowVersion);
        }
        if self.header.build.to_le() != wotlk::BUILD {
            return Err(ProtocolError::BadWowBuild);
        }
        Ok(())
    }
    pub fn get_client_language(&self) -> Result<String, ProtocolError> {
        Ok(str::from_utf8(&self.header.client_info_reversed[8..])
            .map_err(|_| ProtocolError::Utf8Error)?
            .chars()
            .rev()
            .collect())
    }

    // const CLIENTINFO: &[u8] = b"68x\0niW\0SUne";

    pub fn get_client_os_platform(&self) -> Result<(ClientOs, ClientArch), ProtocolError> {
        match (
            &self.header.client_info_reversed[4..7],
            &self.header.client_info_reversed[..3],
        ) {
            (b"niW", b"68x") => Ok((ClientOs::Windows, ClientArch::x86)),
            _ => Err(ProtocolError::UnsupportedOsArch),
        }
    }
}

pub type Salt = [u8; 32];
pub type Verifier = [u8; 32];

#[repr(C, packed)]
#[derive(Clone, Debug, IntoBytes, FromBytes, KnownLayout, Unaligned, Immutable)]
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

impl FixedSizePacket for AuthResponse {}

impl AuthResponse {
    pub fn calculate_B(_b: &BigUint, verifier: &BigUint) -> BigUint {
        use srp6::{g, N};
        let three = BigUint::from(3u32);
        println!("g: {}", Ah(&g));
        println!("_b: {}", Ah(&_b));
        println!("_N: {}", Ah(&*N));
        println!("_g.ModExp(b, _N): {}", Ah(&g.modpow(&_b, &N)));
        println!(
            "_g.ModExp(b, _N) + (v * 3): {}",
            Ah(&(g.modpow(&_b, &N) + (verifier * &three)))
        );

        println!(
            "(_g.ModExp(b, _N) + (v * 3)) % N: {}",
            Ah(&((g.modpow(&_b, &N) + (verifier * &three)) % &*N))
        );
        (g.modpow(&_b, &N) + (verifier * three)) % &*N
    }
}

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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
pub struct AuthServerProof {
    pub cmd: u8,
    pub error: u8,
    pub M2: [u8; 20],
    pub accountFlags: u32,
    pub surveyId: u32,
    pub unkFlags: u16,
}

impl FixedSizePacket for AuthServerProof {}

impl AuthServerProof {
    pub fn validate() -> Result<(), ProtocolError> {
        todo!()
    }
}

pub mod commands {
    pub const AUTH_LOGON_CHALLENGE: u8 = 0x0;
    pub const AUTH_LOGON_PROOF: u8 = 0x1;
    pub const CMD_REALM_LIST: u8 = 0x10;
}

pub type SessionKey = [u8; 40];

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Unaligned, Immutable)]
pub struct AuthClientProof {
    pub cmd: u8,
    pub A: [u8; 32],
    pub M1: [u8; 20],
    pub crc: [u8; 20],
    pub nkeys: u8,
    pub security_flags: u8,
}

impl FixedSizePacket for AuthClientProof {}

#[allow(non_upper_case_globals)]
pub mod srp6 {
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::sync::LazyLock;

    pub const _g: u8 = 0x7;
    pub const g: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_bytes_be(&[_g]));

    const N_str: &str = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7";
    pub const N: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_str_radix(&N_str, 16).unwrap());
    pub const N_BYTES_BE: LazyLock<[u8; 32]> =
        LazyLock::new(|| N.to_bytes_be().try_into().unwrap());

    pub const N_BYTES_LE: LazyLock<[u8; 32]> =
        LazyLock::new(|| N.to_bytes_le().try_into().unwrap());
}

pub struct Ah<'a>(pub &'a BigUint);

impl std::fmt::Display for Ah<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_str_radix(16).to_lowercase())
    }
}

pub struct Aha<'a, const N: usize>(pub &'a [u8; N]);

impl<'a, const N: usize> std::fmt::Display for Aha<'a, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = BigUint::from_bytes_le(self.0);
        write!(f, "{}", b.to_str_radix(16))
    }
}

impl AuthClientProof {
    // static Verifier CalculateVerifier(std::string const& username, std::string const& password, Salt const& salt);
    // static EphemeralKey _B(BigNumber const& b, BigNumber const& v) { return ((_g.ModExp(b, _N) + (v * 3)) % N).ToByteArray<EPHEMERAL_KEY_LENGTH>(); }

    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        salt: &Salt,
        verifier: &Verifier,
        username_upper: &str,
        _b: BigUint,
    ) -> Result<SessionKey, ProtocolError> {
        use srp6::{g, N};

        let A = BigUint::from_bytes_le(&self.A);

        let s = BigUint::from_bytes_le(salt);
        let v = BigUint::from_bytes_be(verifier);

        assert_ne!(&A % &*N, BigUint::ZERO);
        if &A % &*N == BigUint::ZERO {
            return Err(ProtocolError::AuthenticationError(format!(
                "Provided `A` was `mod N`"
            )));
        }

        let B = AuthResponse::calculate_B(&_b, &v);

        let ABhash = sha1_hash_iter(
            A.to_bytes_le()
                .into_iter()
                .chain(B.to_bytes_le().into_iter()),
        );

        let u = BigUint::from_bytes_le(&ABhash);
        let S = (&A * (v.modpow(&u, &N))).modpow(&_b, &N);

        let S_bytes = to_zero_padded_array_le::<32>(&S.to_bytes_le());
        let (s_even, s_odd) = partition(&S_bytes);
        let session_key: SessionKey =
            to_zero_padded_array_le(&interleave(&sha1_hash(s_even), &sha1_hash(s_odd)).unwrap());

        let g_bytes = g.to_bytes_le();
        let NHash = sha1_hash(*N_BYTES_LE);
        let gHash = sha1_hash(g_bytes);

        let NgHash: Vec<u8> = NHash
            .clone()
            .into_iter()
            .zip(gHash)
            .map(|(_n, _g)| _n ^ _g)
            .collect();

        let _I = sha1_hash(username_upper.as_bytes());
        let salt_bytes = s.to_bytes_le();

        eprintln!("A: {}", Ah(&A));
        eprintln!("B: {}", Ah(&B));
        eprintln!("_b: {}", Ah(&_b));
        eprintln!("v: {}", Ah(&v));
        eprintln!("u: {}", Ah(&u));
        eprintln!("S: {}", Ah(&S));
        eprintln!("K: {}", Aha(&session_key));

        let our_M = sha1_hash_iter(
            (NgHash
                .iter()
                .chain(_I.iter())
                .chain(salt_bytes.iter())
                .chain(A.to_bytes_le().iter())
                .chain(B.to_bytes_le().iter())
                .chain(session_key.iter()))
            .copied(),
        );

        eprintln!("our_M: {}", Aha(&our_M));
        eprintln!("their_M: {}", Aha(&self.M1));

        if our_M == self.M1 {
            Ok(session_key)
        } else {
            Err(ProtocolError::AuthenticationError(format!(
                "wrong password probably"
            )))
        }
    }
}

#[derive(Debug, Clone, IntoBytes, FromBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct RealmAuthChallenge {
    pub one: u32,
    pub seed: u32,
    pub seed1: [u8; 16],
    pub seed2: [u8; 16],
}

impl FixedSizePacket for RealmAuthChallenge {}

#[derive(Debug, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct RealmListHeader {
    pub cmd: u8,
    pub packet_size: u16,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct RealmListResult {
    pub header: RealmListHeader,
    pub _unused: u32,
    pub num_realms: u16,
    pub body: [u8],
}

// struct AuthSession
// {
//     uint32 BattlegroupID = 0;
//     uint32 LoginServerType = 0;
//     uint32 RealmID = 0;
//     uint32 Build = 0;
//     std::array<uint8, 4> LocalChallenge = {};
//     uint32 LoginServerID = 0;
//     uint32 RegionID = 0;
//     uint64 DosResponse = 0;
//     Acore::Crypto::SHA1::Digest Digest = {};
//     std::string Account;
//     ByteBuffer AddonInfo;
// };

#[derive(IntoBytes, FromBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct WotlkAuthResponseHeaderFirst {
    build: little_endian::U16,
    login_server_id: u32,
}

#[derive(IntoBytes, FromBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct WotlkAuthResponseHeaderSecond {
    login_server_type: u32,
    local_challenge: [u8; 4],
    region_id: u32,
    battlegroup_id: u32,
    realm_id: u32,
    dos_response: u64,
}

#[derive(IntoBytes, FromBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct WotlkAuthResponse {
    rest: [u8],
}

impl WotlkAuthResponse {
    pub fn new<'b>(
        buf: &'b mut [u8],
        username: &str,
        realm_id: u32,
        challenge_seed: u32,
        session_key: &SessionKey,
    ) -> Result<&'b ProtoPacket<ClientPacketHeader, WotlkAuthResponse>, ProtocolError> {
        macro_rules! write_bytes {
            ($cursor:expr, $data:expr) => {
                std::io::Write::write_all(&mut $cursor, $data.as_bytes()).unwrap()
            };
        }
        let username_upper = username.to_uppercase();
        let header = ClientPacketHeader::new(opcodes::Opcode::CMSG_AUTH_SESSION as u16, 0);

        let our_seed = rand::thread_rng().gen::<u32>();
        let packet_len = {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            let first = WotlkAuthResponseHeaderFirst {
                build: wotlk::BUILD.into(),
                login_server_id: 0,
            };

            let second = WotlkAuthResponseHeaderSecond {
                login_server_type: 0,
                local_challenge: [0; 4],
                region_id: 0,
                battlegroup_id: 0,
                realm_id,
                dos_response: 0,
            };
            write_bytes!(cursor, header);
            write_bytes!(cursor, first);
            write_bytes!(cursor, username_upper);
            write_bytes!(cursor, 0u8); // null terminador
            write_bytes!(cursor, second);

            let mut hashbuf = Vec::new();
            hashbuf.extend(username_upper.as_bytes());
            hashbuf.extend([0; 4]);
            hashbuf.extend(our_seed.to_le_bytes());
            hashbuf.extend(challenge_seed.to_le_bytes());
            hashbuf.extend(session_key);
            let hashbuf_sha = sha1_hash(&hashbuf);
            write_bytes!(cursor, hashbuf_sha);

            let addon_info_length = 0;
            write_bytes!(cursor, addon_info_length);

            cursor.position() as usize
        };

        let packet =
            ProtoPacket::<ClientPacketHeader, Self>::mut_from_bytes(&mut buf[..packet_len])
                .map_err(|e| ProtocolError::ZerocopyError(format!("{e}")))?;

        packet.header.resize(packet_len - 2);

        Ok(packet)
    }
}

impl<H, T> std::fmt::Display for ProtoPacket<H, T>
where
    H: PacketHeader + std::fmt::Debug,
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProtoPacket {{ header: {:?}, body: {:x?} }}",
            self.header, &self.body
        )
    }
}
