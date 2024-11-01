use num_bigint::BigUint;
use wow_proto::opcodes::{AuthOpcode, AuthResult};
use wow_proto::utils::to_zero_padded_array_le;
use wow_proto::{generate_random_bytes, srp6, AuthResponse, ProtocolError, Salt, Verifier};

pub mod auth;

const VERSION_CHALLENGE: [u8; 16] = [
    0xBA, 0xA3, 0x1E, 0x99, 0xA0, 0x0B, 0x21, 0x57, 0xFC, 0x37, 0x3F, 0xB3, 0x69, 0xCD, 0xD2, 0xF1,
];

#[derive(Debug)]
pub struct Account {
    pub id: i32,
    pub username: String,
    pub salt: Salt,
    pub verifier: Verifier,
    pub gmlevel: i32,
    pub active: bool,
}

impl TryFrom<tokio_postgres::Row> for Account {
    type Error = ProtocolError;
    fn try_from(r: tokio_postgres::Row) -> Result<Self, Self::Error> {
        let salt: Vec<u8> = r.get(2);
        let verifier: Vec<u8> = r.get(3);
        Ok(Self {
            id: r.get(0),
            username: r.get(1),
            salt: salt
                .try_into()
                .map_err(|e| ProtocolError::Error(format!("unexpected size for `salt` in db")))?,

            verifier: verifier.try_into().map_err(|e| {
                ProtocolError::Error(format!("unexpected size for `verifier` in db"))
            })?,
            gmlevel: r.get(4),
            active: r.get(5),
        })
    }
}

#[allow(non_snake_case)]
pub fn new_auth_response(salt: &Salt, verifier: &Verifier) -> (AuthResponse, BigUint) {
    let _b = generate_random_bytes::<32>();
    let b = BigUint::from_bytes_le(&_b);
    let v = BigUint::from_bytes_be(verifier);

    let B = AuthResponse::calculate_b(&b, &v);
    let B_bytes = to_zero_padded_array_le::<32>(&B.to_bytes_le());

    (
        AuthResponse {
            opcode: AuthOpcode::AUTH_LOGON_CHALLENGE as u8,
            u1: 0x0,
            u2: AuthResult::Success as u8,
            b: B_bytes,
            u3: 0x1,
            g: [srp6::_g],
            u4: 0x32,
            n: srp6::N_BYTES_LE.to_owned(),
            version_challenge: VERSION_CHALLENGE.clone(),
            salt: salt.to_owned(),
            security_flags: 0x0,
        },
        b,
    )
}
