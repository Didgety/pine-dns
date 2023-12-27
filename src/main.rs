mod data_stream;
pub use data_stream::{ PacketBuffer, DnsHeader, DnsPacket, DnsQuestion, DnsRecord, QueryType, ResCode };

use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};

/// Run the program with ./your_server.sh --resolver <ip:port>
/// Where ip:port is the ip and port of a valid dns resolver
fn main() {
    // resolver ip : port
    let args: Vec<String> = std::env::args().collect();
    let mut recursive = true;
    let resolver = if args.len() == 3 && args[1] == "--resolver"  {
        recursive = false;
        args[2].parse::<SocketAddrV4>().unwrap()       
    } else {
        SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 49810)
    };

    
    
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    
    loop {
        if recursive {
            println!("Resolving Recursively");
            match data_stream::handle_query_recursively(&udp_socket) {
                Ok(_) => {},
                Err(e) => eprintln!("An error occurred: {}", e),
            }  
        } else {
            println!("Resolver: {:#?}", resolver);
            match data_stream::handle_query_with_resolver(&udp_socket, &resolver) {
                Ok(_) => {},
                Err(e) => eprintln!("An error occurred: {}", e),
            }  
        }
             
    }
}
