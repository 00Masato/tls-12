use crate::enums::HandshakeType;

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-5--Server-Hello-Done
// struct { } ServerHelloDone;
#[derive(Debug)]
pub struct ServerHelloDone {
    handshake_type: HandshakeType,
    length: u32,
}

impl ServerHelloDone {
    pub fn read(buf: Vec<u8>, len: u32) -> Self {
        let handshake_type = HandshakeType::ServerHelloDone;
        let length = len;

        ServerHelloDone {
            handshake_type,
            length,
        }
    }
}
