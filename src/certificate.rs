use crate::enums::HandshakeType;
use crate::protocol_version::ProtocolVersion;
use x509_parser::prelude::*;

// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-2--Server-Certificate
// opaque ASN.1Cert<1..2^24-1>;
//
// struct {
//     ASN.1Cert certificate_list<0..2^24-1>;
// } Certificate;
#[derive(Debug)]
pub struct Certificate {
    handshake_type: HandshakeType,
    length: u32,
    certificate_list: Vec<u8>,
}

impl Certificate {
    pub fn read(buffer: Vec<u8>, len: u32) -> Certificate {
        let buffer = buffer;
        Certificate {
            handshake_type: HandshakeType::Certificate,
            length: len,
            certificate_list: buffer,
        }
    }

    pub fn verify(&self) -> bool {
        let mut buffer = &self.certificate_list;
        let res = parse_x509_certificate(buffer);
        match res {
            Ok((rem, cert)) => {
                true
            }
            Err(e) => {
                println!("error: {:?}", e);
                false
            }
        }
    }
}