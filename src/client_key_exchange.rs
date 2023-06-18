// ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-7--Client-Key-Exchange-Message
// struct {
//     select (KeyExchangeAlgorithm) {
//     case rsa:
//     EncryptedPreMasterSecret;
//     case dhe_dss:
//     case dhe_rsa:
//     case dh_dss:
//     case dh_rsa:
//     case dh_anon:
//     ClientDiffieHellmanPublic;
//     } exchange_keys;
// } ClientKeyExchange;
//
// struct {
//     select (PublicValueEncoding) {
//     case implicit: struct { };
//     case explicit: opaque dh_Yc<1..2^16-1>;
//     } dh_public;
// } ClientDiffieHellmanPublic;

use byteorder::{BigEndian, ByteOrder};
use crate::enums::HandshakeType;

#[derive(Debug)]
pub struct ClientKeyExchange {
    handshake_type: HandshakeType,
    length: u32,
    pubkey: Vec<u8>,
}

impl ClientKeyExchange {
    // pub fn new(buffer: Vec<u8>, len: u32) -> ClientKeyExchange {
    //     let handshake_type = HandshakeType::ClientKeyExchange;
    //     let length = len;
    //     let pubkey = buffer[3..].to_vec();
    //
    //     ClientKeyExchange {
    //         handshake_type,
    //         length,
    //         pubkey,
    //     }
    // }

    pub fn encode(client_pub_key: Vec<u8>) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(0x10);
        let key_len = client_pub_key.len() as u32;
        let key_buf = [0 as u8; 4];
        BigEndian::write_u32(&mut buffer, key_len);
        buffer.extend_from_slice(&key_buf[1..]);
        buffer.extend_from_slice(&client_pub_key);
        buffer
    }
}