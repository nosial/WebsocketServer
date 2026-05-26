use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let host = env::var("WSS_TCP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("WSS_TCP_PORT").expect("WSS_TCP_PORT not set");
    let conn_id = env::var("WSS_CONNECTION_ID").expect("WSS_CONNECTION_ID not set");

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).expect("failed to connect");

    let mut buf = conn_id.into_bytes();
    buf.push(b'\n');
    stream.write_all(&buf).unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                for b in buf[..n].iter_mut() {
                    b.make_ascii_uppercase();
                }
                stream.write_all(&buf[..n]).unwrap();
                stream.flush().unwrap();
            }
            Err(_) => break,
        }
    }
}
