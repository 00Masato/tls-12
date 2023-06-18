use rustls::internal::msgs::handshake::HandshakePayload::Certificate;
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
    let mut recv_buf: [u8; 2000] = [0; 2000];
    stream.read(&mut recv_buf)?;

    let parsed_buf = HandshakePayload::parse_packet(&recv_buf);
    for buf in parsed_buf {
        if buf.len() == 0 {
            continue;
        }
        match buf[2] {
            0x02 => {
                println!("server hello");
                let server_hello_payload = HandshakePayload::read_server_hello(buf.to_vec());
                println!("{:?}", server_hello_payload);
            }
            0x0b => {
                println!("certificate");
                let certificate_payload = HandshakePayload::read_certificate(buf.to_vec());
                // verify
                if certificate_payload.verify() {
                    println!("certificate verify success!!!!!");
                } else {
                    println!("certificate verify failed");
                }
            }
            0x0c => {
                println!("server key exchange");
                let server_key_exchange_payload =
                    HandshakePayload::read_server_key_exchange(buf.to_vec());
                println!("{:?}", server_key_exchange_payload);

                // 鍵交換
                server_key_exchange_payload.generate_shared_key();
            }
            0x0e => {
                println!("server hello done");
                let server_hello_done_payload =
                    HandshakePayload::read_server_hello_done(buf[6..].to_vec());
                println!("{:?}", server_hello_done_payload);
            }
            _ => {
                println!("unknown");
            }
        }
        // println!("{:?}", buf);
        // println!("{:?}", buf[4]);
    }
    // println!("{:?}", recv_buf);
    Ok(())
}
