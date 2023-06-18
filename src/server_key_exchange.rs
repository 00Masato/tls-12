// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-3--Server-Key-Exchange-Message
// enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
//     /* may be extended, e.g., for ECDH -- see [TLSECC] */
// } KeyExchangeAlgorithm;
//
// struct {
//     opaque dh_p<1..2^16-1>;
//     opaque dh_g<1..2^16-1>;
//     opaque dh_Ys<1..2^16-1>;
// } ServerDHParams;     /* Ephemeral DH parameters */
//
// struct {
//     select (KeyExchangeAlgorithm) {
//         case dh_anon:
//             ServerDHParams params;
//         case dhe_dss:
//         case dhe_rsa:
//             ServerDHParams params;
//             digitally-signed struct {
//                 opaque client_random[32];
//                 opaque server_random[32];
//                 ServerDHParams params;
//             } signed_params;
//         case rsa:
//         case dh_dss:
//         case dh_rsa:
//     struct {} ;
//     /* message is omitted for rsa, dh_dss, and dh_rsa */
//     /* may be extended, e.g., for ECDH -- see [TLSECC] */
//     };
// } ServerKeyExchange;

use crate::enums::HandshakeType;
use crate::handshake::bytes_to_u32_be;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Debug)]
pub struct ServerKeyExchange {
    handshake_type: HandshakeType,
    length: u32,
    ecdh_server_params: ECDiffieHellmanParam,
}

#[derive(Debug)]
struct ECDiffieHellmanParam {
    curve_type: Vec<u8>,
    named_curve: Vec<u8>,
    pubkey_len: Vec<u8>,
    pubkey: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature_len: Vec<u8>,
    signature: Vec<u8>,
}

impl ServerKeyExchange {
    pub fn read(buffer: Vec<u8>, len: u32) -> ServerKeyExchange {
        let curve_type = buffer[0..1].to_vec();
        let named_curve = buffer[1..3].to_vec();
        let pubkey_len = buffer[3..4].to_vec();
        let pubkey_offset = 4 + bytes_to_u32_be(&pubkey_len) as usize;
        let pubkey = buffer[4..pubkey_offset].to_vec();
        let signature_algorithm = buffer[pubkey_offset..pubkey_offset + 2].to_vec();
        let signature_len = buffer[pubkey_offset + 2..pubkey_offset + 4].to_vec();
        let signature = buffer[pubkey_offset + 4..].to_vec();

        let ecdh_server_params = ECDiffieHellmanParam {
            curve_type,
            named_curve,
            pubkey_len,
            pubkey,
            signature_algorithm,
            signature_len,
            signature,
        };

        ServerKeyExchange {
            handshake_type: HandshakeType::ServerKeyExchange,
            length: len,
            ecdh_server_params,
        }
    }

    // generate ecdh sharedkey
    // ref: https://zenn.dev/satoken/articles/golang-tls1_2_2
    pub fn generate_shared_key(&self) {
        // クライアントの秘密鍵を作る
        let client_secret_key = EphemeralSecret::random();
        // クライアントの公開鍵を作る
        let client_public_key = PublicKey::from(&client_secret_key);
        // サーバーの公開鍵を取得
        println!("ecdh_server_params: {:?}", self.ecdh_server_params);
        println!("pubkey size: {:?}", self.ecdh_server_params.pubkey.len());
        println!("client_public_key size: {:?}", client_public_key.as_bytes().len());
        let server_public_key_bytes: [u8; 32] = self.ecdh_server_params.pubkey[..].try_into().unwrap();
        let server_public_key = PublicKey::from(server_public_key_bytes);

        // 鍵交換
        let client_shared_key = client_secret_key.diffie_hellman(&server_public_key);

        println!("client_public_key: {:?}", client_public_key);
        println!("client_shared_key: {:?}", client_shared_key.as_bytes());
    }
}
