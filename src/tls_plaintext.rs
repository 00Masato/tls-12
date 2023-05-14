use crate::enums::ContentType;
use crate::protocol_version::ProtocolVersion;

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-1--Record-Layer
// struct {
//     ContentType type;
//     ProtocolVersion version;
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
pub struct TLSPlaintext {
    content_type: ContentType,
    version: ProtocolVersion,
    length: u16,
}

impl TLSPlaintext {
    pub fn new(content_type: ContentType, version: ProtocolVersion, length: u16) -> Self {
        TLSPlaintext {
            content_type,
            version,
            length,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(self.content_type.encode());
        bytes.extend(self.version.encode());
        bytes.extend(self.length.to_be_bytes());
        bytes
    }

    pub fn read(buffer: Vec<u8>) -> Self {
        todo!()
    }
}
