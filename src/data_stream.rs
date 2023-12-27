use std::net::{ Ipv4Addr, Ipv6Addr, UdpSocket, SocketAddrV4 };

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

const BUF_SIZE: usize = 512;

pub struct PacketBuffer {
    pub buf: [u8; BUF_SIZE], // each packet is 512 bytes and no more
    pub pos: usize,
}

impl PacketBuffer {
    /// Default constructor
    pub fn new() -> PacketBuffer {
        PacketBuffer{
            buf: [0; BUF_SIZE],
            pos: 0,
        }
    }

    /// current location in the buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// move forward X number of indices in the buffer
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// go to specified index
    fn move_to_pos(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// read a single byte and step forward one
    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// read a single byte without stepping forward
    fn get_u8(&mut self, pos: usize) -> Result<u8> {
        if pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes and step two forward
    /// See also [`read_u8(&mut self)`]
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read_u8()? as u16) << 8) | (self.read_u8()? as u16);

        Ok(res)
    }

    /// Read four bytes and step four forward
    /// See also [`read_u8(&mut self)`]
    fn read_u32(&mut self) -> Result<u32> {
        let res = (self.read_u8()? as u32) << 24
            | (self.read_u8()? as u32) << 16
            | (self.read_u8()? as u32) << 8
            | (self.read_u8()? as u32) << 0;
        
        Ok(res)
    }

    /// Read a qname
    /// ex. [3]www[8]bluesky[3]com[0] appends www.bluesky.com to outstr
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";

        loop {
            // prevents attack by packets with looping instructions
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get_u8(pos)?;

            // Checks if the first two bits are set which indicates a jump to
            // an offset somewhere else in the packet
            if(len & 0xC0) == 0xC0 {
                // move past the label
                if !jumped {
                    self.move_to_pos(pos + 2)?;
                }

                let b2 = self.get_u8(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            } 
            // Reading a single label and appending to the output
            else {
                pos += 1;

                if len == 0 {
                    break;
                }
                // add delimiter to set up the string
                outstr.push_str(delim);
                // extract ascii values and append to outstr
                let str_buf = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buf).to_lowercase());

                delim = ".";
                
                pos += len as usize;
            }
        }

        if !jumped {
            self.move_to_pos(pos)?;
        }

        Ok(())
    }

    /// Write a single byte at the current position and increment pos by one
    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        
        Ok(())
    }

    /// Write a u8 at the current position, increments pos
    /// See also [`write(&mut self, val: u8)`]
    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    /// Write a u16 at the current position, increments pos twice
    /// See also [`write(&mut self, val: u8)`]
    fn write_u16(&mut self, val: u16) -> Result<()> {
        // First byte
        self.write((val >> 8) as u8)?;
        // Last significant byte (second byte in this case)
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    /// Write a u32 at the current position, increments pos thrice
    /// See also [`write(&mut self, val: u8)`] 
    fn write_u32(&mut self, val: u32) -> Result<()> {
        // First byte
        self.write(((val >> 24) & 0xFF) as u8)?;
        // Second byte
        self.write(((val >> 16) & 0xFF) as u8)?;
        // Third byte
        self.write(((val >> 8) & 0xFF) as u8)?;
        // Fourth byte
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    /// Write a query name in label form
    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            // RFC 1035 - max DNS label length of 63 chars
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    /// Unsafe version of write_u8. Does not check if pos is past 512
    fn set_u8(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    ///  Unsafe version of write_u16. Does not check if pos is past 512
    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set_u8(pos, (val >> 8) as u8)?;
        self.set_u8(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResCode {
    NO_ERR      = 0,
    FORM_ERR    = 1,
    SERV_FAIL   = 2,
    NX_DOMAIN   = 3,
    NOT_IMP     = 4,
    REFUSED     = 5,
}

impl ResCode {
    pub fn from_u8(num : u8) -> ResCode {
        match num {
            1     => ResCode::FORM_ERR,
            2     => ResCode::SERV_FAIL,
            3     => ResCode::NX_DOMAIN,
            4     => ResCode::NOT_IMP,
            5     => ResCode::REFUSED,
            0 | _ => ResCode::NO_ERR,
        }
    }
}
/// EXAMPLE HEADER
/// 1 0 0 0 0 0 0 1  1 0 0 0 0 0 0 0
/// - -+-+-+- - - -  - -+-+- -+-+-+-
/// Q    O    A T R  R   Z      R
/// R    P    A C D  A          C
///      C                      O
///      O                      D
///      D                      E
///      E
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,                 // 16 bits

    pub query_res: bool,         // 1 bit (0 query, 1 response)
    pub opcode: u8,              // 4 bits
    pub authoritative: bool,     // 1 bit - authoritative answer

    pub trunc: bool,             // 1 bit - truncated message
    pub rec_des: bool,           // 1 bit - recursion desired
    pub rec_av: bool,            // 1 bit - recursion available

    pub reserved: bool,          // 3 bits - reserved (DNSSEC queries)
    pub auth_data: bool,         // 1 bit  - resolver believes data is authentic (validated by DNSSEC). Uses one of the reserved bits.
    pub checking_disabled: bool, // 1 bit  - disable signature validation if true. Uses one of the reserved bits.
    
    pub res_code: ResCode,       // 4 bits - response code

    pub ques_count: u16,         // 16 bits - entries in Question Section
    pub ans_count: u16,          // 16 bits - entries in Answer Section
    pub auth_count: u16,         // 16 bits - entries in Authority Section
    pub res_count: u16           // 16 bits - entries in Additional Section
}

impl DnsHeader {
    /// Default constructor
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 1234,

            query_res: true,
            opcode: 0,
            authoritative: false,

            trunc: false,
            rec_des: false,
            rec_av: false,

            reserved: false,
            auth_data: false,
            checking_disabled: false,
            
            res_code: ResCode::NO_ERR,

            ques_count: 0,
            ans_count: 0,
            auth_count: 0,
            res_count: 0,
        }
    }

    pub fn read(&mut self, buf: &mut PacketBuffer) -> Result<()> {
        // ID is 2 bytes
        self.id = buf.read_u16()?;
        // Info fields take up another 2 bytes
        let tags = buf.read_u16()?;

        // shift one byte (removes the second byte)
        let tags_first_byte = (tags >> 8) as u8;       
        // Mask and leave only the last significant byte (the second one in this case)
        // 0xFF = 0..0 1111 1111
        let tags_second_byte = (tags & 0xFF) as u8;    

        // Mask to check only the first bit
        self.query_res = (tags_first_byte & (1 << 7)) > 0;
        // Shift 3 bits right and mask the last byte
        // 0x0F = 0000 1111 
        self.opcode = (tags_first_byte >> 3) & 0x0F;
        // Mask to check only the sixth bit
        self.authoritative = (tags_first_byte & (1 << 2)) > 0;

        // Mask to check only the seventh bit
        self.trunc = (tags_first_byte & (1 << 1)) > 0;
        // Mask to check only the eigth bit
        self.rec_des = (tags_first_byte & (1 << 0)) > 0;
        // Mask to check only the first bit
        self.rec_av = (tags_second_byte & (1 << 7)) > 0;

        // Mask to check only the second bit
        self.reserved = (tags_second_byte & (1 << 6)) > 0;
        // Mask to check only the third bit
        self.auth_data = (tags_second_byte & (1 << 5)) > 0;
        // Mask to check only the fourth bit
        self.checking_disabled = (tags_second_byte & (1 << 4)) > 0;
        
        // Mask to check only the last four bits
        self.res_code = ResCode::from_u8(tags_second_byte & 0x0F);

        // The entry counts are all two bytes
        self.ques_count = buf.read_u16()?;
        self.ans_count = buf.read_u16()?;
        self.auth_count = buf.read_u16()?;
        self.res_count = buf.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buf: &mut PacketBuffer) -> Result<()> {
        buf.write_u16(self.id)?;

        buf.write_u8(
            (self.rec_des as u8)
                | ((self.trunc as u8) << 1)
                | ((self.authoritative as u8) << 2)
                | (self.opcode << 3)
                | ((self.query_res as u8) << 7) as u8,   
        )?;

        buf.write_u8(
            (self.res_code as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.auth_data as u8) << 5)
                | ((self.reserved as u8) << 6)
                | ((self.rec_av as u8) << 7)
        )?;

        buf.write_u16(self.ques_count)?;
        buf.write_u16(self.ans_count)?;
        buf.write_u16(self.auth_count)?;
        buf.write_u16(self.res_count)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum QueryType {
    UNKNOWN(u16),
    A,      // 1 - Alias
    NS,     // 2 - Name Server
    CNAME,  // 5 - Canonical Name
    MX,     // 15 - Mail Exchange
    AAAA    // 28 - IPv6 Alias
}

impl QueryType {
    pub fn to_u16(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28
        }
    }

    pub fn from_u16(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    } 
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    pub name: String,
    pub q_type: QueryType,
}

impl DnsQuestion {
    /// Constructor
    pub fn new(name: String, q_type: QueryType) -> DnsQuestion {
        DnsQuestion { 
            name: name,
            q_type: q_type,
        }
    }

    /// Read the question section from a dns packet
    pub fn read(&mut self, buf: &mut PacketBuffer) -> Result<()> {
        buf.read_qname(&mut self.name)?;
        self.q_type = QueryType::from_u16(buf.read_u16()?);
        // class
        let _ = buf.read_u16()?; 

        Ok(())
    }

    /// Write the question section to a PacketBuffer
    /// Should be used only after writing DnsHeader to the PacketBuffer
    pub fn write(&self, buf: &mut PacketBuffer) -> Result<()> {
        buf.write_qname(&self.name)?;

        let q_type_u16 = self.q_type.to_u16();
        buf.write_u16(q_type_u16)?;
        buf.write_u16(1)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        q_type: u16,
        len: u16,
        ttl: u32,
    },
    A { // 1
        domain: String,
        addr_v4: Ipv4Addr,
        ttl: u32,
    }, 
    NS { // 2
        domain: String,
        host: String,
        ttl: u32,
    }, 
    CNAME { // 5
        domain: String,
        host: String,
        ttl: u32,
    }, 
    MX { // 15
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, 
    AAAA { // 28
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, 
}

impl DnsRecord {

    pub fn read(buf: &mut PacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buf.read_qname(&mut domain)?;

        let q_type_u16 = buf.read_u16()?;
        let q_type = QueryType::from_u16(q_type_u16);
        let _ = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let len = buf.read_u16()?;

        match q_type {
            QueryType::A => {
                let raw_addr_v4 = buf.read_u32()?;
                let addr_v4 = Ipv4Addr::new(
                    ((raw_addr_v4 >> 24) & 0xFF) as u8,
                    ((raw_addr_v4 >> 16) & 0xFF) as u8,
                    ((raw_addr_v4 >> 8) & 0xFF)  as u8,
                    ((raw_addr_v4 >> 0) & 0xFF)  as u8,
                );

                Ok(DnsRecord::A { 
                    domain: domain, 
                    addr_v4: addr_v4, 
                    ttl: ttl, 
                })
            }
            QueryType::AAAA => {
                let raw_addr_1 = buf.read_u32()?;
                let raw_addr_2 = buf.read_u32()?;
                let raw_addr_3 = buf.read_u32()?;
                let raw_addr_4 = buf.read_u32()?;
                let addr_v6 = Ipv6Addr::new(
                    ((raw_addr_1 >> 16 & 0xFFFF)) as u16,
                    ((raw_addr_1 >> 0  & 0xFFFF)) as u16,
                    ((raw_addr_2 >> 16 & 0xFFFF)) as u16,
                    ((raw_addr_2 >> 0  & 0xFFFF)) as u16,
                    ((raw_addr_3 >> 16 & 0xFFFF)) as u16,
                    ((raw_addr_3 >> 0  & 0xFFFF)) as u16,
                    ((raw_addr_4 >> 16 & 0xFFFF)) as u16,
                    ((raw_addr_4 >> 0  & 0xFFFF)) as u16,
                );

                Ok(DnsRecord::AAAA { 
                    domain: domain, 
                    addr: addr_v6, 
                    ttl: ttl 
                })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buf.read_qname(&mut ns)?;

                Ok(DnsRecord::NS { 
                    domain: domain, 
                    host: ns, 
                    ttl: ttl 
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buf.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME { 
                    domain: domain, 
                    host: cname, 
                    ttl: ttl 
                })
            }
            QueryType::MX => {
                let prio = buf.read_u16()?;
                let mut mx = String::new();
                buf.read_qname(&mut mx)?;

                Ok(DnsRecord::MX { 
                    domain: domain, 
                    priority: prio, 
                    host: mx, 
                    ttl: ttl 
                })
            }
            QueryType::UNKNOWN(_) => {
                buf.step(len as usize)?;

                Ok(DnsRecord::UNKNOWN { 
                    domain: domain, 
                    q_type: q_type_u16,
                    len: len, 
                    ttl: ttl 
                })
            }
        }
    }

    
    pub fn write(&self, buf: &mut PacketBuffer) -> Result<usize> {
        let start = buf.pos;

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr_v4,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::A.to_u16())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;
                buf.write_u16(4)?;

                let octets = addr_v4.octets();
                buf.write_u8(octets[0])?;
                buf.write_u8(octets[1])?;
                buf.write_u8(octets[2])?;
                buf.write_u8(octets[3])?;
            }
            DnsRecord::NS { 
                ref domain, 
                ref host, 
                ttl 
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::NS.to_u16())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?;

                buf.write_qname(host)?;
                let size = buf.pos() - (pos + 2);
                buf.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME { 
                ref domain,
                ref host, 
                ttl 
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::CNAME.to_u16())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?;

                buf.write_qname(host)?;

                let size = buf.pos() - (pos + 2);
                buf.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX { 
                ref domain, 
                priority, 
                ref host, 
                ttl 
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::MX.to_u16())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?;

                buf.write_u16(priority)?;
                buf.write_qname(host)?;

                let size = buf.pos() - (pos + 2);
                buf.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA { 
                ref domain,
                ref addr,
                ttl 
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::AAAA.to_u16())?;
                buf.write_u16(1)?;
                buf.write_u32(ttl)?;
                buf.write_u16(16)?;

                for octet in &addr.segments() {
                    buf.write_u16(*octet)?;
                }
            }        
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping unknown record: {:?}", self);
            }                 
        }

        Ok(buf.pos() - start)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Default constructor
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    // Read the contents of a PacketBuffer into a DnsPacket
    pub fn from_buf(buf: &mut PacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buf)?;

        for _ in 0..result.header.ques_count {
            let mut ques = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            ques.read(buf)?;
            result.questions.push(ques);
        }

        for _ in 0..result.header.ans_count {
            let rec = DnsRecord::read(buf)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.auth_count {
            let rec = DnsRecord::read(buf)?;
            result.authorities.push(rec);
        }
        
        for _ in 0..result.header.res_count {
            let rec = DnsRecord::read(buf)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    /// Write the contents of the packet to a PacketBuffer
    pub fn write(&mut self, buf: &mut PacketBuffer) -> Result<()> {
        self.header.ques_count = self.questions.len() as u16;
        self.header.ans_count = self.answers.len() as u16;
        self.header.auth_count = self.authorities.len() as u16;
        self.header.res_count = self.resources.len() as u16;

        self.header.write(buf)?;

        for ques in &self.questions {
            ques.write(buf)?;
        }
        
        for rec in &self.answers {
            rec.write(buf)?;
        }

        for rec in &self.authorities {
            rec.write(buf)?;
        }

        for rec in &self.resources {
            rec.write(buf)?;
        }

        Ok(())
    }
}

/// Perform a lookup of a DnsQuestion from a remote nameserver
/// Uses a given resolver (ip and port)
pub fn lookup(id: u16, ques: &DnsQuestion, resolver: &SocketAddrV4) -> Result<DnsPacket> {
    let udp_socket = UdpSocket::bind(("127.0.0.1", 43210)).expect("Failed to bind to lookup address");

    let mut pak = DnsPacket::new();

    pak.header.id = id;
    pak.header.query_res = false;
    pak.header.rec_des = true;
    pak.questions.push(ques.clone());
    let mut req_buf = PacketBuffer::new();
    pak.write(&mut req_buf)?;

    udp_socket.send_to(&req_buf.buf[0..req_buf.pos], resolver)?;
    let mut res_buf = PacketBuffer::new();
    udp_socket.recv_from(&mut res_buf.buf)?;
    
    DnsPacket::from_buf(&mut res_buf)
}

/// Handle an incoming packet
/// Uses a given resolver (ip and port)
pub fn handle_query(udp_socket: &UdpSocket, resolver: &SocketAddrV4) -> Result<()> {
    let mut req_buf = PacketBuffer::new();

    let (size, source) = udp_socket.recv_from(&mut req_buf.buf)?;

    println!("Received {} bytes from {}", size, source);

    let mut req = DnsPacket::from_buf(&mut req_buf)?;

    // println!("REQ!!!!!!!"); 
    // println!("{:#?}", req.header.id); 
    // println!("{:#?}", req.questions); 

    let mut response = DnsPacket::new();
    response.header.id = req.header.id;
    response.header.query_res = true;
    response.header.opcode = req.header.opcode;
    response.header.rec_av = false;
    response.header.rec_des = req.header.rec_des; 
    response.header.res_code = 
    if req.header.opcode == 0 { 
        ResCode::NO_ERR 
    } 
    else { 
        ResCode::NOT_IMP 
    };

    if response.header.res_code == ResCode::NO_ERR {
        
        for _ in 0..req.header.ques_count as usize {         
            // println!("Received query: {:?}", req.questions[i]);
            if let Some(ques) = req.questions.pop() {
                // println!("Received query: {:?}", ques);
                response.questions.push(ques);
                if let Ok(result) = lookup(req.header.id, &response.questions.last().unwrap(), resolver) {
                    for i in 0..result.answers.len() {                   
                        response.answers.push(result.answers[i].clone());
                    }
                } else {
                    response.header.res_code = ResCode::SERV_FAIL;
                }  
            }                                        
        }
    }

    // println!("RESP!!!!!!!"); 
    // println!("{:#?}", response.header);

    let mut res_buf = PacketBuffer::new();
    response.write(&mut res_buf)?;

    let len = res_buf.pos();
    let data = res_buf.get_range(0, len)?;

    udp_socket.send_to(data, source)?;

    Ok(())
}