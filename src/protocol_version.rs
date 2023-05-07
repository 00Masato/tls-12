// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-1--Record-Layer
// struct {
//     uint8 major;
//     uint8 minor;
// } ProtocolVersion;
//
// This ProtocolVersion support only TLS1.2.
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub fn new(major: u8, minor: u8) -> Self {
        ProtocolVersion { major, minor }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        let major: u8 = match self.major {
            1 => 0x03,
            _ => 0x00,
        };
        let minor: u8 = match self.minor {
            2 => 0x03,
            _ => 0xff,
        };

        bytes.push(major);
        bytes.push(minor);
        bytes
    }
}
