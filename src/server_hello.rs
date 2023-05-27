use crate::handshake::{Random, SessionId};
use crate::protocol_version::ProtocolVersion;
use byteorder::{BigEndian, ByteOrder};
use rustls::internal::msgs::handshake::ServerExtension;
use crate::enums::HandshakeType;
use chrono::{TimeZone, Utc};


// https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-1-3--Server-Hello
// struct {
//     ProtocolVersion server_version;
//     Random random;
//     SessionID session_id;
//     CipherSuite cipher_suite;
//     CompressionMethod compression_method;
//     select (extensions_present) {
//     case false:
//     struct {};
//     case true:
//     Extension extensions<0..2^16-1>;
//     };
// } ServerHello;
#[derive(Debug)]
pub struct ServerHelloPayload {
    handshake_type: HandshakeType,
    length: u32,
    protocol_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite: Vec<u8>,
    compression_method: Vec<u8>,
    extensions: Vec<ServerExtension>,
}

impl ServerHelloPayload {
    pub fn read(buf: Vec<u8>, len: u32) -> Self {
        let handshake_type = HandshakeType::ServerHello;
        let length = len;
        let protocol_version = ProtocolVersion {
            major: buf[0],
            minor: buf[1],
        };
        let gmt_unix_time = BigEndian::read_u32(&buf[2..6]) as i64;
        let random = Random {
            gmt_unix_time: Utc.timestamp_opt(gmt_unix_time, 0).unwrap(),
            random_bytes: buf[6..34].to_vec(),
        };
        let session_id_len = buf[34] as usize;
        let session_id_end = 34 + session_id_len;
        let session_id = SessionId {
            len: session_id_len,
            data: buf[34..session_id_end].try_into().unwrap(),
        };
        let cipher_suite = buf[session_id_end..session_id_end + 2].to_vec();
        let compression_method = buf[session_id_end + 2..session_id_end + 3].to_vec();
        let extensions = vec![];

        ServerHelloPayload {
            handshake_type,
            length,
            protocol_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        }
    }
}
