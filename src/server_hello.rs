use rustls::internal::msgs::handshake::ServerExtension;
use crate::handshake::{Random, SessionId};
use crate::protocol_version::ProtocolVersion;

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
pub struct ServerHello {
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
