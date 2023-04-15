use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::AsFd;
use tls_12::handshake::ClientHello;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:1337")?;
    let mut client_hello = ClientHello::new();
    let mut buf = client_hello.encode();
    stream.write_all(&mut buf)?;

    let mut result = [0; 1024];
    stream.read(&mut result)?;
    println!("{:?}", result);
    Ok(())
}