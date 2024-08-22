use anyhow::Result;

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

    fn step(&mut self, step: usize) -> Result<()> {
        self.pos += step;
        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let byte = self.buf[self.pos];
        self.pos += 1;

        Ok(byte)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }

        Ok(self.buf[pos])
    }

    // read a range of bytes as mentioned by the length preceding a part of the qname
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
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
                return Err("max jumps exceeded".into());
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
