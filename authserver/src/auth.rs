use num_bigint::BigUint;
use wow_proto::{sha1_digest, utils::to_zero_padded_array_le, Salt, Sha1Digest, Verifier};
use zerocopy::IntoBytes;

pub fn calculate_verifier(username_upper: &str, password: &str, salt: &Salt) -> Verifier {
    use wow_proto::srp6::{g, N};
    let creds = format!("{}:{}", username_upper, password.to_ascii_uppercase());

    let xb = BigUint::from_bytes_le(&sha1_digest!(salt, sha1_digest!(creds)));
    let v = g.modpow(&xb, &N);
    to_zero_padded_array_le(&v.to_bytes_be()) // TODO le/be confusion
}

#[allow(unused_imports, dead_code)]
mod test {
    use num_bigint::BigUint;
    use num_traits::Num;
    use srp6::{g, N};
    use wow_proto::{
        sha1_digest,
        srp6::{self, N_BYTES_LE},
        utils::{interleave, partition, to_zero_padded_array_le},
        Ah, AuthResponse, Salt, SessionKey, Sha1Digest,
    };

    use zerocopy::IntoBytes;

    use crate::auth::calculate_verifier;

    fn ah_be<T: AsRef<[u8]>>(v: &T) -> String {
        BigUint::from_bytes_be(v.as_ref())
            .to_str_radix(16)
            .to_lowercase()
    }

    fn ah_le<T: AsRef<[u8]>>(v: &T) -> String {
        BigUint::from_bytes_le(v.as_ref())
            .to_str_radix(16)
            .to_lowercase()
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_auth() {
        let As = "5f6b9d567090dad3f92837905a269ef74654bc28cb89616cb9fbe507f408c1b6";
        let Bs = "87985e249baef9e8a579943f3cf142998b420836a8bc89445cf932322565f70a";
        let _bs = "84E860000948722DE0A59FA39DCAD920CC396E66FE684B1AE50288B43924A93C";

        let salt = "fe9a4b960df07b07fda99b5b72f75ff514c466fa8dc090ee08388c35b7c528e3";
        let verifier = "5CDDBD8DB378422A2CF948638A8F38616F102911F14EBDAAD634FD4BACF4BC18";

        let A = BigUint::from_str_radix(As, 16).unwrap();
        // let Ab = A.to_bytes_be();
        let B = BigUint::from_str_radix(Bs, 16).unwrap();
        // let Bb = B.to_bytes_be();

        assert_eq!(&ah_be(&A.to_bytes_be()), As);
        assert_eq!(&ah_be(&B.to_bytes_be()), Bs);

        let _b = BigUint::from_str_radix(_bs, 16).unwrap();

        let s = BigUint::from_str_radix(salt, 16).unwrap();
        let v = BigUint::from_str_radix(verifier, 16).unwrap();

        assert_ne!(&A % &*N, BigUint::ZERO);

        let ABhash = sha1_digest!(A.to_bytes_le(), B.to_bytes_le());

        assert_eq!(&ah_le(&ABhash), "a33209b9872e5fce13a7eb5f0f4b180ba6f4d707");

        let u = BigUint::from_bytes_le(&ABhash);
        let S = (&A * (v.modpow(&u, &N))).modpow(&_b, &N);

        let three = BigUint::from(3u32);

        assert_eq!(
            g.modpow(&_b, &N),
            BigUint::from_str_radix(
                "8395EE389508DA2199E8722AEF503A1B4E14F01E544F0D6330D33F5D7304FA30",
                16
            )
            .unwrap()
        );

        assert_eq!(
            g.modpow(&_b, &N) + (&v * &three),
            BigUint::from_str_radix(
                "019A2F26E1AF71A0A020D44B558EFDE33F9B456B54283B4663B372374079E32E78",
                16
            )
            .unwrap()
        );

        assert_eq!(
            (g.modpow(&_b, &N) + (&v * &three) % &*N),
            BigUint::from_str_radix(
                "87985E249BAEF9E8A579943F3CF142998B420836A8BC89445CF932322565F70A",
                16
            )
            .unwrap()
        );

        assert_eq!((g.modpow(&_b, &N) + (&v * &three) % &*N), B);

        let S_bytes = to_zero_padded_array_le::<32>(&S.to_bytes_le());
        let (s_even, s_odd) = partition(&S_bytes);
        let session_key: SessionKey = to_zero_padded_array_le(
            &interleave(&sha1_digest!(s_even), &sha1_digest!(s_odd)).unwrap(),
        );

        assert_eq!(
            &S.to_str_radix(16),
            "2025c04d15b7f228f78711b5d7d8549e753748907d4dbacdbf62af3e1e9f333c"
        );

        assert_eq!(
            &ah_le(&session_key),
            "6e0a08c588032c38d9efac9568f81b19ba85ae7ed5ab5088550fdce4ab9ae7d6a509e1bc2c0df253"
        );

        let g_bytes = g.to_bytes_le();
        let NHash = sha1_digest!(*N_BYTES_LE);
        let gHash = sha1_digest!(&g_bytes);

        let NgHash: Vec<u8> = NHash
            .clone()
            .into_iter()
            .zip(gHash)
            .map(|(_n, _g)| _n ^ _g)
            .collect();

        assert_eq!(&ah_le(&NHash), "136529087794c76424272695999d0de5d3576080");
        assert_eq!(&ah_le(&gHash), "b4a75264e15ea8347e5bbe9688eea1dde9e71b5d");
        assert_eq!(&ah_le(&NgHash), "a7c27b6c96ca6f505a7c98031173ac383ab07bdd");

        let _I = sha1_digest!("TLIPP");
        assert_eq!(&ah_le(&_I), "95ed43716c7efc75442d9bb2b7e8dd9b5c85ef3a");

        let salt_bytes = s.to_bytes_le();

        let our_M = sha1_digest!(
            NgHash,
            _I,
            salt_bytes,
            A.to_bytes_le(),
            B.to_bytes_le(),
            session_key
        );

        assert_eq!(&ah_le(&our_M), "d1620cf47d49e65e46433dc3069231ea9c84f2d9");
        // | _N = 894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7
        // | u = A33209B9872E5FCE13A7EB5F0F4B180BA6F4D707
        // | S = 2025c04d15b7f228f78711b5d7d8549e753748907d4dbacdbf62af3e1e9f333c
        // | NHash = 136529087794c76424272695999d0de5d3576080
        // | gHash = b4a75264e15ea8347e5bbe9688eea1dde9e71b5d
        // | NgHash = a7c27b6c96ca6f505a7c98031173ac383ab07bdd
        // | s (aka salt) = fe9a4b960df07b07fda99b5b72f75ff514c466fa8dc090ee08388c35b7c528e3
        // | _v = 5CDDBD8DB378422A2CF948638A8F38616F102911F14EBDAAD634FD4BACF4BC18
        // | _I = 95ed43716c7efc75442d9bb2b7e8dd9b5c85ef3a
        // | _g.ModExp(_b, _N) = 8395EE389508DA2199E8722AEF503A1B4E14F01E544F0D6330D33F5D7304FA30
        // | _g.ModExp(_b, _N) + (_v * 3) = 019A2F26E1AF71A0A020D44B558EFDE33F9B456B54283B4663B372374079E32E78
        // | _g.ModExp(_b, _N) + (_v * 3) % N = 87985E249BAEF9E8A579943F3CF142998B420836A8BC89445CF932322565F70A
        // | A: 5f6b9d567090dad3f92837905a269ef74654bc28cb89616cb9fbe507f408c1b6
        // | B: 87985e249baef9e8a579943f3cf142998b420836a8bc89445cf932322565f70a
        // | ABhash: a33209b9872e5fce13a7eb5f0f4b180ba6f4d707
        // | vModExpU_N = 50157CADC4E87315F0BFAC91792FD412B27951B07E96D29A79B1054240309AE6
        // | AvModExpU_N = 1DD9A377D098BB16B6E58C2F63025E5A39BAE8905B5C8251F6E11D7DE00A626CCB789D064F92171844E6674F188A6885D2C459DA00FCACF79976FEF056858584
        // | final = 2025C04D15B7F228F78711B5D7D8549E753748907D4DBACDBF62AF3E1E9F333C
        // | ourM = d1620cf47d49e65e46433dc3069231ea9c84f2d9
        // | clientM = d1620cf47d49e65e46433dc3069231ea9c84f2d9
        // | K = 6e0a08c588032c38d9efac9568f81b19ba85ae7ed5ab5088550fdce4ab9ae7d6a509e1bc2c0df253
        // | let As = "5f6b9d567090dad3f92837905a269ef74654bc28cb89616cb9fbe507f408c1b6";
        // | let Bs = "87985e249baef9e8a579943f3cf142998b420836a8bc89445cf932322565f70a";
        // | let _bs = "84E860000948722DE0A59FA39DCAD920CC396E66FE684B1AE50288B43924A93C";
    }

    #[test]
    fn test_auth_response() {
        // let response = AuthResponse { opcode: 0, u1: 0, u2: 0, B: [0x25, 0x22, 0x4E, 0xEE, 0xAC, 0x50, 0xA3, 0xA7, 0xEC, 0x37, 0xA2, 0x13, 0x6, 0x80, 0x15, 0x6A, 0x6D, 0xBE, 0xC3, 0x16, 0x18, 0xB6, 0xF2, 0xDD, 0x5C, 0xE6, 0xFB, 0x30, 0xEC, 0x96, 0xD3, 0x80], u3: 1, g: [7], u4: 20, N: [B7, 9B, 3E, 2A, 87, 82, 3C, AB, 8F, 5E, BF, BF, 8E, B1, 1, 8, 53, 50, 6, 29, 8B, 5B, AD, BD, 5B, 53, E1, 89, 5E, 64, 4B, 89], salt: [0xDB, 0x8A, 0xF4, 0x7A, 0x69, 0x43, 0x7C, 0xC0, 0x95, 0x5F, 0x14, 0xCF, 0xC9, 0x81, 0xDE, 0xB, 0x95, 0xBF, 0x7, 0xB, 0x5C, 0xAE, 0x6, 0x57, 0x51, 0x85, 0xFA, 0x7F, 0x76, 0x1B, 0x1, 0x8B], unk1: [BA, A3, 1E, 99, A0, B, 21, 57, FC, 37, 3F, B3, 69, CD, D2, F1], securityFlags: 0 };
    }

    #[test]
    fn test_verifier() {
        let salt = BigUint::from_str_radix(
            "fe9a4b960df07b07fda99b5b72f75ff514c466fa8dc090ee08388c35b7c528e3",
            16,
        )
        .unwrap();

        let salt_bytes = to_zero_padded_array_le::<32>(&salt.to_bytes_le());

        let _I = sha1_digest!("TLIPP");
        assert_eq!(&ah_le(&_I), "95ed43716c7efc75442d9bb2b7e8dd9b5c85ef3a");
        let v = calculate_verifier("TLIPP", "kuusysi69", &salt_bytes);
        assert_eq!(
            &ah_be(&v),
            "5cddbd8db378422a2cf948638a8f38616f102911f14ebdaad634fd4bacf4bc18"
        );
    }

    #[test]
    fn test_verifier2() {
        let salt: Salt = [
            0xDB, 0x8A, 0xF4, 0x7A, 0x69, 0x43, 0x7C, 0xC0, 0x95, 0x5F, 0x14, 0xCF, 0xC9, 0x81,
            0xDE, 0xB, 0x95, 0xBF, 0x7, 0xB, 0x5C, 0xAE, 0x6, 0x57, 0x51, 0x85, 0xFA, 0x7F, 0x76,
            0x1B, 0x1, 0x8B,
        ];

        dbg!(ah_le(&salt));
        let salt = BigUint::from_bytes_le(&salt);

        let salt_bytes = to_zero_padded_array_le::<32>(&salt.to_bytes_le());

        let _I = sha1_digest!("TLIPP");
        assert_eq!(&ah_le(&_I), "95ed43716c7efc75442d9bb2b7e8dd9b5c85ef3a");
        let v = calculate_verifier("TLIPP", "kuusysi69", &salt_bytes);
        assert_eq!(
            &ah_be(&v),
            "45d9d906286c34051b6d5240383c9a02b00a1a58ff75385f4911f5300f482c04"
        );
    }

    #[test]
    fn test_verifier3() {
        let salt = BigUint::from_str_radix(
            "0f7a2d6aee53816e4b59b9a8d2320ce7538cfe7c85b4f96b98a6c95cca949ecc",
            16,
        )
        .unwrap();
        let salt = to_zero_padded_array_le::<32>(&salt.to_bytes_le());

        let verifier = calculate_verifier(&"tlipp".to_uppercase(), "kuusysi69", &salt);
    }

    #[test]
    fn test_palli() {
        let _b = BigUint::from_str_radix(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            16,
        )
        .unwrap();

        let salt: Salt = [
            0xDB, 0x8A, 0xF4, 0x7A, 0x69, 0x43, 0x7C, 0xC0, 0x95, 0x5F, 0x14, 0xCF, 0xC9, 0x81,
            0xDE, 0xB, 0x95, 0xBF, 0x7, 0xB, 0x5C, 0xAE, 0x6, 0x57, 0x51, 0x85, 0xFA, 0x7F, 0x76,
            0x1B, 0x1, 0x8B,
        ];

        let salt = BigUint::from_bytes_le(&salt);

        let salt_bytes = to_zero_padded_array_le::<32>(&salt.to_bytes_le());

        let _I = sha1_digest!("TLIPP");
        assert_eq!(&ah_le(&_I), "95ed43716c7efc75442d9bb2b7e8dd9b5c85ef3a");
        let v = calculate_verifier("TLIPP", "kuusysi69", &salt_bytes);

        assert_eq!(
            &ah_be(&v),
            "45d9d906286c34051b6d5240383c9a02b00a1a58ff75385f4911f5300f482c04"
        );

        let B = AuthResponse::calculate_b(&_b, &BigUint::from_bytes_be(&v));

        assert_eq!(
            &ah_be(&B.to_bytes_be()),
            "716b0decd9bf504d43e98720c9251196c990cd67005d9a8d364aafddaf7b206b"
        );
    }
    #[test]
    fn test_calculate_b() {
        let salt: Salt = [
            0xDB, 0x8A, 0xF4, 0x7A, 0x69, 0x43, 0x7C, 0xC0, 0x95, 0x5F, 0x14, 0xCF, 0xC9, 0x81,
            0xDE, 0xB, 0x95, 0xBF, 0x7, 0xB, 0x5C, 0xAE, 0x6, 0x57, 0x51, 0x85, 0xFA, 0x7F, 0x76,
            0x1B, 0x1, 0x8B,
        ];

        let salt = BigUint::from_bytes_le(&salt);

        let salt_bytes = to_zero_padded_array_le::<32>(&salt.to_bytes_le());

        let _I = sha1_digest!("TLIPP");
        assert_eq!(&ah_le(&_I), "95ed43716c7efc75442d9bb2b7e8dd9b5c85ef3a");
        let v = calculate_verifier("TLIPP", "kuusysi69", &salt_bytes);

        let B = BigUint::from_str_radix(
            "134C414A680FDCEB5C5B95ADC1BD94FAD72C7CCE5144BFBE30A1E7C8E57AAD9C",
            16,
        )
        .unwrap();
        let _b = BigUint::from_str_radix(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeee", // note: intentionally "deadbeee" last
            16,
        )
        .unwrap();

        let calculated_B = AuthResponse::calculate_b(&_b, &BigUint::from_bytes_be(&v));
        println!("{} should be {}", Ah(&B), Ah(&calculated_B));
        assert_eq!(B, calculated_B);
    }
}
