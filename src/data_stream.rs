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
        let res = ((self.read_u8()? as u16) << 8 | self.read_u8()? as u16);

        Ok(res)
    }

    /// Read four bytes and step four forward
    /// See also [`read_u8(&mut self)`]
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | ((self.read_u8()? as u32) << 0);
        
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
        self.write((val >> 24) as u8)?;
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

            ques_count: 1,
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
                | ((self.query_res as u8) << 7),   
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
    A,
}

impl QueryType {
    pub fn to_u16(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_u16(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
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