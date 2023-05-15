use crate::client_hello::ClientHelloPayload;
use crate::enums;
use crate::enums::ContentType::Handshake;
use crate::enums::HandshakeType::ClientHello;
use crate::enums::{AlertDescription, AlertLevel, HandshakeType};
use crate::protocol_version::ProtocolVersion;
use crate::server_hello::ServerHelloPayload;
use crate::tls_plaintext::TLSPlaintext;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::handshake::ServerExtension;

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
        let server_hello_payload = ServerHelloPayload::read(buffer[6..].to_vec());

        server_hello_payload
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

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-4-1--Hello-Messages
// struct {
//              uint32 gmt_unix_time;
//              opaque random_bytes[28];
//          } Random;
#[derive(Debug)]
pub struct Random {
    pub gmt_unix_time: u32,
    pub random_bytes: Vec<u8>,
}
