mod data_stream;
pub use data_stream::{ PacketBuffer, DnsHeader };

use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                // let response = [];
                // udp_socket
                //     .send_to(&response, source)
                //     .expect("Failed to send response");
                let head = DnsHeader::new();
                let mut pak = PacketBuffer::new();
                head.write(&mut pak).unwrap();
                udp_socket
                    .send_to(&pak.buf, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
