use bytes::{BytesMut, BufMut};

fn main() {
    let mut buf = BytesMut::with_capacity(80);
    for i in 0..80 {
        buf.put_u8(i as u8);
    }
    buf.resize(80, 0);
    println!("{:x}", buf);
}
