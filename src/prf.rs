// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#5--HMAC-and-the-Pseudorandom-Function


use ring::hmac;
use bytes::{Bytes, BytesMut};

// Ref: https://github.com/rustls/rustls/blob/main/rustls/src/tls12/prf.rs#L33-L36
pub fn prf(length: usize, secret: &[u8], seed: &[u8], label: &[u8]) -> BytesMut {
    let seed = [label, seed].concat();
    p_hash(length, secret, &seed)
}

// Ref: https://github.com/rustls/rustls/blob/main/rustls/src/tls12/prf.rs#L10-L24
// Ref: https://github.com/sat0ken/go-tcpip/blob/main/tls_prf.go
// Ref: https://cs.opensource.google/go/go/+/refs/heads/master:src/crypto/tls/prf.go;drc=b3bc8620f89153fddc1a30ee17c1d93654ed4314;l=27
fn p_hash(length: usize, secret: &[u8], seed: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(length);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    // A(0) = seed
    let a = hmac::sign(&hmac_key, seed);

    while length < buf.len() {
        // A(i) = HMAC_hash(secret, A(i-1))
        let a = hmac::sign(&hmac_key, a.as_ref());
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let p = hmac::sign(&hmac_key, [a.as_ref(), seed].concat().as_ref());
        buf.extend_from_slice(p.as_ref());
    }
    buf.resize(length, 0);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    // Ref: https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
    fn check_sha256() {
        let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
        let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
        let label = b"test label";
        let expect_result = b"\xe3\xf2\x29\xba\x72\x7b\xe1\x7b\x8d\x12\x26\x20\x55\x7c\xd4\x53\xc2\xaa\xb2\x1d\x07\xc3\xd4\x95\x32\x9b\x52\xd4\xe6\x1e\xdb\x5a\x6b\x30\x17\x91\xe9\x0d\x35\xc9\xc9\xa4\x6b\x4e\x14\xba\xf9\xaf\x0f\xa0\x22\xf7\x07\x7d\xef\x17\xab\xfd\x37\x97\xc0\x56\x4b\xab\x4f\xbc\x91\x66\x6e\x9d\xef\x9b\x97\xfc\xe3\x4f\x79\x67\x89\xba\xa4\x80\x82\xd1\x22\xee\x42\xc5\xa7\x2e\x5a\x51\x10\xff\xf7\x01\x87\x34\x7b\x66";

        assert_eq!(&prf(100, secret, seed, label)[..], &expect_result[..]);
    }
}