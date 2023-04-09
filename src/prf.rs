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
