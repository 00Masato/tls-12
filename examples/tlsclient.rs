use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::AsFd;
use tls_12::handshake::HandshakePayload;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:1337")?;
    let mut client_hello = HandshakePayload::client_hello();
    let mut buf = client_hello.encode();
    println!("{:?}", buf);
    stream.write_all(&mut buf)?;

    // let mut result = [0; 1024];
    // stream.read(&mut result)?;
    // println!("{:?}", result);

    // ref: https://github.com/sat0ken/go-tcpip/blob/e6defa2b8b44031df4407ff228df7aa631d8d287/example/tls12_handshake_clientauth.go#L41-L50
    let mut recv_buf: [u8; 1500] = [0; 1500];
    stream.read(&mut recv_buf)?;
    println!("{:?}", recv_buf);
    Ok(())
}