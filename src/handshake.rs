use crate::certificate::Certificate;
use crate::client_hello::ClientHelloPayload;
use crate::enums;
use crate::enums::ContentType::Handshake;
use crate::enums::HandshakeType::ClientHello;
use crate::enums::{AlertDescription, AlertLevel, HandshakeType};
use crate::protocol_version::ProtocolVersion;
use crate::server_hello::ServerHelloPayload;
use crate::server_key_exchange::ServerKeyExchange;
use crate::tls_plaintext::TLSPlaintext;
use chrono::{DateTime, Utc};
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::handshake::ServerExtension;
use crate::server_hello_done::ServerHelloDone;

// Ref: https://github.com/rustls/rustls/blob/main/rustls/src/msgs/handshake.rs#L108-L111
#[derive(Debug)]
pub struct SessionId {
    pub len: usize,
    pub data: [u8; 32],
}

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-2--Alert-Protocol
// struct {
//           AlertLevel level;
//           AlertDescription description;
//       } Alert;
struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4--Handshake-Protocol
// struct {
//           HandshakeType msg_type;    /* handshake type */
//           uint24 length;             /* bytes in message */
//           select (HandshakeType) {
//               case hello_request:       HelloRequest;
//               case client_hello:        ClientHello;
//               case server_hello:        ServerHello;
//               case certificate:         Certificate;
//               case server_key_exchange: ServerKeyExchange;
//               case certificate_request: CertificateRequest;
//               case server_hello_done:   ServerHelloDone;
//               case certificate_verify:  CertificateVerify;
//               case client_key_exchange: ClientKeyExchange;
//               case finished:            Finished;
//           } body;
//       } Handshake;
#[derive(Debug)]
pub struct HandshakePayload {
    msg_type: HandshakeType,
    length: u32,
}

// MasterSecretの情報を格納
// ref: https://github.com/sat0ken/go-tcpip/blob/fc2b35be0ca462df93c33c22b0081c06ee4c8788/tls_type.go#L171
#[derive(Debug)]
pub struct MasterSecretInfo {
    MasterSecret: Vec<u8>,
    PreMasterSecret: Vec<u8>,
    ClientRandom: Vec<u8>,
    ServerRandom: Vec<u8>,
}

impl HandshakePayload {
    pub fn client_hello() -> Self {
        let length = ClientHelloPayload::new().encode().len() as u32;

        HandshakePayload {
            msg_type: ClientHello,
            length,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let client_hello_payload = ClientHelloPayload::new().encode();

        // encode TLSPlainText
        let protocol_version = ProtocolVersion::new(1, 2);
        let tls_plaintext = TLSPlaintext::new(
            Handshake,
            protocol_version,
            (&client_hello_payload.len() + 4) as u16,
        );
        bytes.extend(&tls_plaintext.encode());

        // encode HandshakePayload
        bytes.push(*&self.msg_type.encode());
        // length is size 3 Vec<u8>
        let encoded_length = self.length.to_be_bytes()[1..].to_vec();
        bytes.extend(&encoded_length);
        bytes.extend(&client_hello_payload);

        bytes
    }

    pub fn read_server_hello(buffer: Vec<u8>) -> ServerHelloPayload {
        let len = bytes_to_u32_be(&buffer[0..2]);
        let server_hello_payload = ServerHelloPayload::read(buffer[6..].to_vec(), len);

        server_hello_payload
    }

    pub fn read_certificate(buffer: Vec<u8>) -> Certificate {
        let buffer = buffer;
        let len = bytes_to_u32_be(&buffer[3..6]);
        let certificate = Certificate::read(buffer[12..].to_vec(), len);

        certificate
    }

    pub fn read_server_key_exchange(buffer: Vec<u8>) -> ServerKeyExchange {
        let buffer = buffer;
        let len = bytes_to_u32_be(&buffer[3..6]);
        let server_key_exchange = ServerKeyExchange::read(buffer[6..].to_vec(), len);

        server_key_exchange
    }

    pub fn read_server_hello_done(buffer: Vec<u8>) -> ServerHelloDone {
        let buffer = buffer;
        let len = bytes_to_u32_be(&buffer[3..6]);
        let server_hello_done = ServerHelloDone::read(buffer[12..].to_vec(), len);

        server_hello_done
    }

    pub fn parse_packet(data: &[u8]) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        // TLSPlaintext delimiter
        let delimiter = b"\x16\x03\x03";

        let mut start = 0;
        while let Some(offset) = data[start..]
            .windows(delimiter.len())
            .position(|window| window == delimiter)
        {
            result.push(data[start..start + offset].to_vec());
            start += offset + delimiter.len();
        }
        result.push(data[start..].to_vec());

        result
    }
}

pub fn bytes_to_u32_be(bytes: &[u8]) -> u32 {
    let mut result = 0;
    for byte in bytes {
        result = (result << 8) + *byte as u32;
    }
    result
}

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-4-1--Hello-Messages
// struct {
//              uint32 gmt_unix_time;
//              opaque random_bytes[28];
//          } Random;
#[derive(Debug)]
pub struct Random {
    pub gmt_unix_time: DateTime<Utc>,
    pub random_bytes: Vec<u8>,
}
