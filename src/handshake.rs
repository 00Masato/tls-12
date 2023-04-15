use crate::enums::{AlertDescription, AlertLevel, HandshakeType};

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

// struct {
//           AlertLevel level;
//           AlertDescription description;
//       } Alert;
struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

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
struct HandShake {
    msg_type: HandshakeType,
    length: u32,
    body: Vec<u8>,
}

// struct {
//              uint32 gmt_unix_time;
//              opaque random_bytes[28];
//          } Random;
struct Random {
    gmt_unix_time: u32,
    random_bytes: Vec<u8>,
}

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
struct ClientHello {
    client_hello: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suites: Vec<u8>,
    compression_methods: Vec<u8>,
    extensions: Vec<u8>,
}

impl ClientHello {
    fn new() -> Self {
        ClientHello {
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
            cipher_suites: vec![0; 2],
            compression_methods: vec![0; 1],
            extensions: vec![0; 2],
        }
    }
}