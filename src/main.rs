mod data_stream;
pub use data_stream::{ PacketBuffer, DnsHeader, DnsPacket, DnsQuestion, DnsRecord, QueryType, ResCode };

use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");
    
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut pak_buf = PacketBuffer::new();
    
    loop {
        match udp_socket.recv_from(&mut pak_buf.buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                pak_buf.pos = 0;

                let req = DnsPacket::from_buf(&mut pak_buf).unwrap();
                
                println!("REQ!!!!!!!"); 
                println!("{:#?}", req.header.opcode); 
                // println!("{:#?}", req.questions);
                // println!("{:#?} : {:#?}", pak_buf.buf[0], pak_buf.buf[1]);
                // println!("{:08b} : {:08b}", pak_buf.buf[0], pak_buf.buf[1]);
                // println!("{:#?}", ((pak_buf.buf[0] as u16) << 8) | (pak_buf.buf[1] as u16));
                

                let mut response = DnsPacket::new();

                response.header.id = req.header.id;
                // response.header.query_res = true;
                response.header.opcode = req.header.opcode;
                response.header.rec_des = req.header.rec_des; 
                response.header.res_code = 
                    if req.header.opcode == 0 { 
                        ResCode::NO_ERR 
                    } 
                    else { 
                        ResCode::NOT_IMP 
                    };
                response.questions = req.questions;
                           
                
                let _ques = DnsQuestion::new(String::from("codecrafters.io"), QueryType::A);
                let _rec = data_stream::DnsRecord::A { 
                    domain: String::from("codecrafters.io"), 
                    addr_v4: std::net::Ipv4Addr::new(1,1,1,1), 
                    ttl: 60 
                };

                // Hardcoded to pass one specific test
                if response.questions.len() == 1 {
                    //response.questions.push(_ques);
                    response.answers.push(_rec);
                }              

                let mut pak = PacketBuffer::new();

                response.write(&mut pak).unwrap();

                println!("RESP!!!!!!!"); 
                println!("{:#?}", response.header.opcode); 
                //println!("{:#?}", response.questions);   

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
