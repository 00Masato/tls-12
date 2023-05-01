use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ECPointFormat::ANSIX962CompressedPrime;
use rustls::internal::msgs::handshake::{ClientExtension, ServerExtension};
use rustls::SignatureScheme::RSA_PSS_SHA256;
use crate::enums::{AlertDescription, AlertLevel, HandshakeType};
use crate::enums::HandshakeType::ClientHello;

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#6-2--Record-Layer
// struct {
//           uint8 major;
//           uint8 minor;
//       } ProtocolVersion;
struct ProtocolVersion {
    major: u8,
    minor: u8,
}

// Ref: https://github.com/rustls/rustls/blob/main/rustls/src/msgs/handshake.rs#L108-L111
struct SessionId {
    len: usize,
    data: [u8; 32],
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
pub struct HandshakePayload {
    msg_type: HandshakeType,
    length: u32,
    body: Vec<u8>,
}

impl HandshakePayload {
    pub fn client_hello() -> Self {
        HandshakePayload {
            msg_type: ClientHello,
            length: ClientHelloPayload::new().encode().len() as u32,
            body: ClientHelloPayload::new().encode(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x16);
        bytes.push(0x03);
        bytes.push(0x01);
        bytes.push(0x00);
        bytes.push((&self.body.len() + 4) as u8);
        match self.msg_type {
            ClientHello => {
                bytes.push(0x01);
            }
            _ => {}
        }
        // length to Vec<u8> size 3(u24)
        let length_u24 = self.length.to_be_bytes()[1..].to_vec();
        bytes.extend(&length_u24);

        bytes.extend(&self.body);
        bytes
    }
}

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-4-1--Hello-Messages
// struct {
//              uint32 gmt_unix_time;
//              opaque random_bytes[28];
//          } Random;
struct Random {
    gmt_unix_time: u32,
    random_bytes: Vec<u8>,
}

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-1-2--Client-Hello
//  struct {
//           ProtocolVersion client_version;
//           Random random;
//           SessionID session_id;
//           CipherSuite cipher_suites<2..2^16-2>;
//           CompressionMethod compression_methods<1..2^8-1>;
//           select (extensions_present) {
//               case false:
//                   struct {};
//               case true:
//                   Extension extensions<0..2^16-1>;
//           };
//       } ClientHello;
pub struct ClientHelloPayload {
    client_hello: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suites: Vec<u8>,
    compression_methods: Vec<u8>,
    extensions: Vec<ClientExtension>,
}

impl ClientHelloPayload {
    pub fn new() -> Self {
        ClientHelloPayload {
            // TLS 1.2
            client_hello: ProtocolVersion {
                major: 0x03,
                minor: 0x03,
            },
            random: Random {
                gmt_unix_time: 0,
                random_bytes: vec![0; 28],
            },
            session_id: SessionId {
                len: 0,
                data: [0; 32],
            },
            // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            cipher_suites: vec![0xc0, 0x2c],
            compression_methods: vec![0; 1],
            // I referred to the extension when connecting with openssl
            // done command is `openssl s_client -connect 127.0.0.1:1337 -tls1_2 < /dev/null`
            extensions: vec![
                // ec_point_formats
                ClientExtension::ECPointFormats(vec![ANSIX962CompressedPrime; 1]),
                // signature_algorithms
                ClientExtension::SignatureAlgorithms(vec![RSA_PSS_SHA256; 1]),
            ]
        }
    }

    // encode ClientHello type to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.client_hello.major);
        buf.push(self.client_hello.minor);
        buf.extend_from_slice(&self.random.gmt_unix_time.to_be_bytes());
        buf.extend_from_slice(&self.random.random_bytes);
        buf.push(self.session_id.len as u8);
        // cipher_suites length to Vec<u8> size 2(u16)
        let cipher_suites_len: Vec<u8> = (2 as u16).to_be_bytes()[..2].to_vec();
        buf.extend(&cipher_suites_len);
        buf.extend_from_slice(&self.cipher_suites);
        // compression length
        buf.push(self.compression_methods.len() as u8);
        buf.extend_from_slice(&self.compression_methods);
        let extensions = &self.extensions;
        // extensions length to Vec<u8> size 2(u16)
        buf.push(0x00);
        buf.push(0x0e);
        for extension in extensions {
            buf.extend_from_slice(&extension.get_encoding());
        }
        buf
    }
}

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
struct ServerHello {
    server_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite: Vec<u8>,
    compression_method: Vec<u8>,
    extensions: Vec<ServerExtension>,
}

impl ServerHello {
    pub fn decode() -> Self {
        todo!()
    }
}