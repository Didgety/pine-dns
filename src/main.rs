mod data_stream;
pub use data_stream::{ PacketBuffer, DnsHeader, DnsPacket, DnsQuestion, DnsRecord, QueryType, ResCode };

use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};

/// Run the program with ./your_server.sh --resolver <ip:port>
/// Where ip:port is the ip and port of a valid dns resolver
fn main() {
    // resolver ip : port
    let args: Vec<String> = std::env::args().collect();
    let resolver = if args.len() == 3 && args[1] == "--resolver"  {
        args[2].parse::<SocketAddrV4>().unwrap()
    } else {
        SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 49810)
    };

    println!("Resolver: {:#?}", resolver);
    
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    
    
    loop {
        data_stream::handle_query(&udp_socket, &resolver).expect("Failed to process query");
    }
}
