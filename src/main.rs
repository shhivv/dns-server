use anyhow::Result;
mod structure;
use std::fs::File;
use std::io::Read;
use structure::{BytePacketBuffer, DnsPacket};

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    #[allow(clippy::unused_io_amount)]
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buf(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.additional {
        println!("{:#?}", rec);
    }

    Ok(())
}
