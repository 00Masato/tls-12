use crate::handshake::{Random, SessionId};
use crate::protocol_version::ProtocolVersion;
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ECPointFormat::{ANSIX962CompressedPrime, Uncompressed};
use rustls::internal::msgs::handshake::ClientExtension;
use rustls::{NamedGroup, SignatureScheme};

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-1-2--Client-Hello
// struct {
//     ProtocolVersion client_version;
//     Random random;
//     SessionID session_id;
//     CipherSuite cipher_suites<2..2^16-2>;
//     CompressionMethod compression_methods<1..2^8-1>;
//     select (extensions_present) {
//         case false:
//             struct {};
//         case true:
//             Extension extensions<0..2^16-1>;
//     };
// } ClientHello;
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
                gmt_unix_time: Utc::now(),
                random_bytes: vec![0; 28],
            },
            session_id: SessionId {
                len: 0,
                data: [0; 32],
            },
            // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            cipher_suites: vec![0xc0, 0x30],
            compression_methods: vec![0; 1],
            // I referred to the extension when connecting with openssl
            // done command is `openssl s_client -connect 127.0.0.1:1337 -tls1_2 < /dev/null`
            extensions: vec![
                // ec_point_formats
                ClientExtension::ECPointFormats(vec![Uncompressed, ANSIX962CompressedPrime]),
                // signature_algorithms
                ClientExtension::SignatureAlgorithms(
                    // Ref: https://github.com/rustls/rustls/blob/main/rustls/src/verify.rs#L420
                    vec![
                        SignatureScheme::ECDSA_NISTP384_SHA384,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ED25519,
                        SignatureScheme::RSA_PSS_SHA512,
                        SignatureScheme::RSA_PSS_SHA384,
                        SignatureScheme::RSA_PSS_SHA256,
                        SignatureScheme::RSA_PKCS1_SHA512,
                        SignatureScheme::RSA_PKCS1_SHA384,
                        SignatureScheme::RSA_PKCS1_SHA256,
                    ],
                ),
                // supported_groups(elliptic_curves)
                ClientExtension::NamedGroups(vec![NamedGroup::X25519, NamedGroup::secp521r1]),
            ],
        }
    }

    // encode ClientHello type to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.client_hello.major);
        buf.push(self.client_hello.minor);
        let gmt_unix_time = &self.random.gmt_unix_time;
        let mut gmt_unix_time_buf = [0; 4];
        BigEndian::write_u32(&mut gmt_unix_time_buf, gmt_unix_time.timestamp() as u32);
        buf.extend_from_slice(gmt_unix_time_buf.as_ref());
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
        buf.push(0x29);
        for extension in extensions {
            buf.extend_from_slice(&extension.get_encoding());
        }
        buf
    }
}
