// Ref: https://www.rfc-editor.org/rfc/rfc5246#section-5


pub fn prf(secret: usize, seed: usize, label: usize) -> usize {
    let seed = label + seed;
    p_hash(secret, label, seed)
}

// Ref: https://github.com/sat0ken/go-tcpip/blob/main/tls_prf.go
// Ref: https://cs.opensource.google/go/go/+/refs/heads/master:src/crypto/tls/prf.go;drc=b3bc8620f89153fddc1a30ee17c1d93654ed4314;l=27
fn p_hash(result: usize, secret: usize, seed: usize) -> usize {
    // let mut result = 0;
    // let mut a = seed;
    // let mut i = 0;
    // while i < 255 {
    //     a = hmac_sha256(secret, a);
    //     let mut b = hmac_sha256(secret, a);
    //     b = hmac_sha256(secret, b);
    //     result = result ^ b;
    //     i = i + 1;
    // }
    // result
    todo!()
}