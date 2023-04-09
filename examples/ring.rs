use ring::{digest, hmac};

fn main() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret_key");
    let message = b"Hello, world!";
    let signature = hmac::sign(&key, message);
    println!("{:?}", signature);
}
