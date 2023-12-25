mod data_stream;
pub use data_stream::{ PacketBuffer, DnsHeader, DnsQuestion, QueryType };

use std::net::{UdpSocket, Ipv4Addr};

use crate::data_stream::DnsRecord;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let head = DnsHeader::new();
                let ques = DnsQuestion::new(String::from("codecrafters.io"), QueryType::A);
                let rec = DnsRecord::A { 
                    domain: String::from("codecrafters.io"), 
                    addr_v4: Ipv4Addr::new(1,1,1,1), 
                    ttl: 60 
                };

                let mut pak = PacketBuffer::new();

                head.write(&mut pak).unwrap();
                ques.write(&mut pak).unwrap();
                rec.write(&mut pak).unwrap();
                
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
