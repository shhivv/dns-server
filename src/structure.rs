#![allow(clippy::upper_case_acronyms)]
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

    pub fn pos(&self) -> usize {
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

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            bail!("End of buffer")
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?; // high byte
        self.write((val & 0xFF) as u8)?; // low byte
        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
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
    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            bail!("End of buffer");
        }
        Ok(&self.buf[start..(start + len)])
    }


    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
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

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        //                     query name              type   class
        //        -----------------------------------  -----  -----
        // HEX    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  00 01  00 01
        // ASCII     g  o  o  g  l  e     c  o  m
        // DEC    6                    3           0       1      1
        // follows the length-label-length-label-...-0 structure

        for label in qname.split('.') {
            let len = label.len();
            if len > 63 {
                bail!("max label length is 63")
            }

            self.write(len as u8)?;
            for b in label.as_bytes() {
                self.write(*b)?;
            }
        }

        self.write(0)?;

        Ok(())
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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write(
            (self.rec_des as u8)
                | ((self.trunc_msg as u8) << 1)
                | ((self.auth_ans as u8) << 2)
                | (self.opcode << 3)
                | ((self.query_res as u8) << 7) as u8,
        )?;

        buffer.write((self.rcode as u8) | ((self.z as u8) << 4) | ((self.rec_ava as u8) << 7))?;

        buffer.write_u16(self.qdcount)?;
        buffer.write_u16(self.anscount)?;
        buffer.write_u16(self.nscount)?;
        buffer.write_u16(self.arcount)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}
impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 6,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            6 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
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
    pub fn new(name: String, qtype: QueryType) -> Self {
        Self {
            name,
            qtype,
            class: 1,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.name = buffer.read_qname()?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        self.class = buffer.read_u16()?; // class, usually always 1

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let type_num = self.qtype.to_num();
        buffer.write_u16(type_num)?;
        buffer.write_u16(1)?; // class

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
    NS {
        domain: String,
        class: u16,
        ttl: u32,
        len: u16,
        host: String,
    },
    CNAME {
        domain: String,
        class: u16,
        ttl: u32,
        len: u16,
        host: String,
    },
    MX {
        domain: String,
        class: u16,
        ttl: u32,
        len: u16,
        host: String,
        priority: u16,
    },
    AAAA {
        domain: String,
        class: u16,
        ttl: u32,
        len: u16,
        ip: u128,
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
            QueryType::AAAA => Ok(DnsRecord::AAAA {
                domain,
                class,
                ttl,
                len,
                ip: (buf.read_u16()? as u128) << 16
                    | (buf.read_u16()? as u128) << 16
                    | (buf.read_u16()? as u128) << 16
                    | (buf.read_u16()? as u128) << 16
                    | (buf.read_u16()? as u128) << 16
                    | (buf.read_u16()? as u128) << 16
                    | (buf.read_u16()? as u128) << 16
                    | buf.read_u16()? as u128,
            }),
            QueryType::NS => Ok(DnsRecord::NS {
                domain,
                class,
                ttl,
                len,
                host: buf.read_qname()?,
            }),
            QueryType::CNAME => Ok(DnsRecord::CNAME {
                domain,
                class,
                ttl,
                len,
                host: buf.read_qname()?,
            }),
            QueryType::MX => {
                let priority = buf.read_u16()?;
                let host = buf.read_qname()?;


                Ok(DnsRecord::MX {
                    domain,
                    class,
                    priority,
                    host,
                    ttl,
                    len
                })
            }
            _ => {
                buf.step(len as usize)?;
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype,
                    class,
                    ttl,
                    len,
                })
            },
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ip,
                ttl,
                ..
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;
                buffer.write_u32(ip)?;
            },
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
                ..
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(&host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            },
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
                ..
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
                ..
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref ip,
                ttl,
                ..
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for i in 0..4 {
                    buffer.write_u32((ip >> (i * 32)) as u32)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
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
    pub fn new() -> Self {
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
            let mut qn = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            qn.read(buf)?;
            res.questions.push(qn)
        }

        for _ in 0..res.header.anscount {
            res.answers.push(DnsRecord::from(buf)?)
        }
        for _ in 0..res.header.nscount {
            res.authorities.push(DnsRecord::from(buf)?)
        }
        for _ in 0..res.header.arcount {
            res.additional.push(DnsRecord::from(buf)?)
        }

        Ok(res)
    }
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.qdcount = self.questions.len() as u16;
        self.header.anscount = self.answers.len() as u16;
        self.header.nscount = self.authorities.len() as u16;
        self.header.arcount = self.additional.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.additional {
            rec.write(buffer)?;
        }

        Ok(())
    }


    pub fn get_random_a(&self) -> Option<u32> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { ip, .. } => Some(*ip),
                _ => None,
            })
            .next()
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<u32> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.additional
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, ip, .. } if domain == host => Some(ip),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname)
            .map(|(_, host)| host)
            .next()
    }


}
