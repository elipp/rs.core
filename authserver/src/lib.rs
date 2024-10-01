use client::{
    generate_random_bytes, srp6, to_zero_padded_array_le, AuthChallenge, AuthResponse,
    ProtocolError, Salt, Verifier,
};
use num_bigint::BigUint;

pub mod auth;

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

pub fn new_auth_response(salt: &Salt, verifier: &Verifier) -> AuthResponse {
    use srp6::{g, N};
    let _b = generate_random_bytes::<32>();
    let b = BigUint::from_bytes_le(&_b);
    let v = BigUint::from_bytes_le(verifier);
    let three = BigUint::from(3u32);

    let B = (g.modpow(&b, &N) + (v * three)) % &*N;
    let B_bytes = to_zero_padded_array_le::<32>(&B.to_bytes_le());

    AuthResponse {
        opcode: 0x0,
        u1: 0x0,
        u2: crate::auth::AuthResult::Success as u8,
        B: B_bytes,
        u3: 0x1,
        g: [srp6::_g],
        u4: 0x32,
        N: srp6::N_BYTES_LE.to_owned(),
        salt: salt.to_owned(),
        unk1: generate_random_bytes(),
        securityFlags: 0x0,
    }
}
