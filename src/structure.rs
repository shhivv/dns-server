#![allow(clippy::upper_case_acronyms)]
use crate::structure::QueryType::{A, UNKNOWN};
use anyhow::{bail, Result};


// this will represent our entire query
pub struct BytePacketBuffer {
    pub buf: [u8; 512], // 512 bytes because that's the udp packet limit
    pub pos: usize,
}
impl BytePacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            bail!("End of buffer")
        }
        let byte = self.buf[self.pos];
        self.pos += 1;

        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16); // read 2 bytes and put it into one u16
        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            bail!("End of buffer");
        }

        Ok(self.buf[pos])
    }

    // read a range of bytes as mentioned by the length preceding a part of the qname
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            bail!("End of buffer");
        }
        Ok(&self.buf[start..(start + len)])
    }

    fn read_qname(&mut self) -> Result<String> {
        // locally track pos because we might encounter jumps
        let mut pos = self.pos();
        let mut out = String::new();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";

        loop {
            // to prevent a infinite jump loop
            if jumps_performed > max_jumps {
                bail!("max jumps exceeded");
            }

            let len = self.get(pos)?;

            // a jump directive is set by making the two most significant bits of the length byte 1 ie, 11 000000
            // the jump position is found by combining this bit with the next bit and discarding the first 2 bits,
            // which is done by xor-ing with 11 000000 00000000 or 0xc0 to unset the bits.
            // we can check if a jump directive is set by and-ing with 0xc0 and matching with 0xc0 to see if the first
            // two bits are set. pretty cool ngl

            if (len & 0xC0) == 0xC0 {
                // since the two bytes will indicate the jump position, we can jump those two bytes
                // in the main buffer. since we do this here we don't need to do it after the loop.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;

                // first we cast len into a 16-bit integer so that we can store both bytes in one int,
                // then we xor the value with 0xC0 to unset the two msbs.
                // then we left shift it by 8 bits, so that we can move our first byte as the high byte
                // which will fill the last 8 bits with 0s, if we didn't do that, we will overwrite the b1 w b2.
                // and we finally or the result with b2 to combine the two bytes into one 16-bit integer.
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;

                pos = offset as usize;

                jumped = true;
                jumps_performed += 1
            } else {
                // no jump set so we continue past the length byte
                pos += 1;

                if len == 0 {
                    break;
                }

                // we are pre-pushing the delim because we don't want a dot at the end of our qname
                out.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize)?;
                out.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        // if no jumps occurred, we can update the buffer pos with the local pos, thereby we are past the qname
        // section. if jumps occurred, we already updated it.
        if !jumped {
            self.seek(pos)?;
        }
        Ok(out)
    }
}

/// only implementing a few common result codes, the entire list is here
/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    XRRSET = 7,
    NOTAUTH = 8,
    NOTZONE = 9,
}

impl ResultCode {
    pub fn from_num(n: u8) -> Self {
        match n {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            6 => ResultCode::YXDOMAIN,
            7 => ResultCode::XRRSET,
            8 => ResultCode::NOTAUTH,
            9 => ResultCode::NOTZONE,
            _ => ResultCode::NOERROR,
        }
    }
}

// header structure
// 86 2a 01 20 00 01 00 00 00 00 00 00
// in this example, 86 2a are the 16-bit ids
// 01 20 represent the flags from query_res to rcode
// 00 01, 00 00, 00 00, 00 00 represent the u16 counts
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bit uid
    pub query_res: bool,
    pub opcode: u8, // 4 bits but we can use the low nibble
    pub auth_ans: bool,
    pub trunc_msg: bool,
    pub rec_des: bool,
    pub rec_ava: bool,
    pub z: u8, // 3 bits fsr
    pub rcode: ResultCode,
    pub qdcount: u16,
    pub anscount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        Self {
            id: 0,
            query_res: false,
            opcode: 0,
            auth_ans: false,
            trunc_msg: false,
            rec_des: false,
            rec_ava: false,
            z: 0,
            rcode: ResultCode::NOERROR,
            qdcount: 0,
            anscount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.id = buf.read_u16()?;

        // 0 0 0 0 0 0 0 1  0 0 1 0 0 0 0 0
        // - -+-+-+- - - -  - -+-+- -+-+-+-
        // Q    O    A T R  R   Z      R
        // R    P    A C D  A          C
        //      C                      O
        //      O                      D
        //      D                      E
        //      E
        let a = buf.read()?;
        let b = buf.read()?;

        // im using a mask to get only the required bits ,and then I shift it to right most side.
        self.query_res = ((a & 0x80) >> 7) > 0;
        self.opcode = (a & 0x78) >> 3;
        self.auth_ans = ((a & 0x4) >> 2) > 0;
        self.trunc_msg = ((a & 0x2) >> 1) > 0;
        self.rec_des = (a & 0x1) > 0;

        self.rec_ava = ((b & 0x80) >> 7) > 0;
        self.z = (b & 0x70) >> 4;
        self.rcode = ResultCode::from_num(b & 0xF);

        self.qdcount = buf.read_u16()?;
        self.anscount = buf.read_u16()?;
        self.nscount = buf.read_u16()?;
        self.arcount = buf.read_u16()?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
}

impl QueryType {
    fn from_num(num: u16) -> QueryType {
        match num {
            1 => A,
            _ => UNKNOWN(num),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub class: u16,
}

impl DnsQuestion {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            qtype: QueryType::UNKNOWN(0),
            class: 1,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.name = buffer.read_qname()?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        self.class = buffer.read_u16()?; // class, usually always 1

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
    },
    A {
        domain: String,
        class: u16,
        ttl: u32,
        len: u16,
        ip: u32,
    },
}

impl DnsRecord {
    pub fn from(buf: &mut BytePacketBuffer) -> Result<Self> {
        let domain = buf.read_qname()?;

        let qtype = QueryType::from_num(buf.read_u16()?);
        let class = buf.read_u16()?;
        let ttl = (buf.read_u16()? << 8) as u32 | buf.read_u16()? as u32;
        let len = buf.read_u16()?;

        match qtype {
            QueryType::A => Ok(DnsRecord::A {
                domain,
                class,
                ttl,
                len,
                ip: (buf.read_u16()? as u32) << 16 | buf.read_u16()? as u32,
            }),
            _ => Ok(DnsRecord::UNKNOWN {
                domain,
                qtype,
                class,
                ttl,
                len,
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
    fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additional: vec![],
        }
    }

    pub fn from_buf(buf: &mut BytePacketBuffer) -> Result<Self> {
        let mut res = DnsPacket::new();
        res.header.read(buf)?;

        for _ in 0..res.header.qdcount {
            let mut qn = DnsQuestion::new();
            qn.read(buf)?;
            res.questions.push(qn)
        }

        for _ in 0..res.header.anscount {
            res.answers.push(DnsRecord::from(buf)?)
        }
        for _ in 0..res.header.nscount {
            res.answers.push(DnsRecord::from(buf)?)
        }
        for _ in 0..res.header.arcount {
            res.answers.push(DnsRecord::from(buf)?)
        }

        Ok(res)
    }
}
