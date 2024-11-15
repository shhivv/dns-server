use anyhow::Result;
mod structure;
use crate::structure::{DnsQuestion, QueryType, ResultCode};
use std::net::{Ipv4Addr, UdpSocket};
use structure::{BytePacketBuffer, DnsPacket};

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket>{

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 1337; // random id
    packet.header.qdcount = 1; // we only need google's addr, nothing else.
    packet.header.rec_des = true;

    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buf = BytePacketBuffer::new();
    packet.write(&mut req_buf)?;

    socket.send_to(&req_buf.buf[0..req_buf.pos], server)?; // only send what has been written to

    let mut res_buf = BytePacketBuffer::new();
    socket.recv_from(&mut res_buf.buf)?;
    DnsPacket::from_buf(&mut res_buf)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket>{
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?; // 198.41.0.4
    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;


        if !response.answers.is_empty() && response.header.rcode == ResultCode::NOERROR{
            return Ok(response);
        }

        if response.header.rcode == ResultCode::NXDOMAIN{
            return Ok(response);
        }


        if let Some(new_ns) = response.get_resolved_ns(qname){
            ns = Ipv4Addr::from(new_ns);
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname){
            Some(x) => x,
            None => return Ok(response)
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a(){
            ns = Ipv4Addr::from(new_ns);
        } else {
            return Ok(response);
        }

    }

}
fn handle_query(socket: &UdpSocket) -> Result<()>{
    let mut req_buf = BytePacketBuffer::new();
    let (_len, src) = socket.recv_from(&mut req_buf.buf)?;

    let mut req = DnsPacket::from_buf(&mut req_buf)?;

    let mut packet = DnsPacket::new();
    packet.header.id = req.header.id;
    packet.header.rec_des = true;
    packet.header.rec_ava = true;
    packet.header.query_res = true;

    if let Some(question) = req.questions.pop() {
        println!("Question: {:?}", question);
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rcode = result.header.rcode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.additional {
                println!("Additional: {:?}", rec);
                packet.additional.push(rec);
            }
        } else {
            packet.header.rcode = ResultCode::SERVFAIL;
        }
    }
    else{
        packet.header.rcode = ResultCode::FORMERR;
    }


    let mut res_buf = BytePacketBuffer::new();
    packet.write(&mut res_buf)?;

    socket.send_to(&res_buf.buf[0..res_buf.pos()], src)?;



    Ok(())
}

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("Something went wrong: {}", e),
        }
    }
}
