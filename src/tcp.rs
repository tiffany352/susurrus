use {session, handshake};
use std::net::{TcpStream, ToSocketAddrs};
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use std::io::{Read, Write};
use std::io;

pub struct NoiseTcpStream {
    tcp: TcpStream,
    local: session::Session,
    remote: session::Session
}

fn write_frame(stream: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
    let mut l = vec![];
    l.write_u32::<LittleEndian>(buf.len() as u32).unwrap();
    try!(stream.write(&l[..]));
    try!(stream.write(buf));
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    if try!(stream.read(&mut len_buf)) != 4 {
        return Err(io::Error::new(io::ErrorKind::Other, "Could not read frame length"))
    }
    let len = LittleEndian::read_u32(&len_buf[..]) as usize;
    let mut buf = vec![0u8; len];
    assert!(try!(stream.read(&mut buf)) == len);
    Ok(buf)
}

impl NoiseTcpStream {
    pub fn connect<A: ToSocketAddrs>(local: Option<session::KeyPair>,
                                     remote: Option<session::PubKey>,
                                     addr: A) -> io::Result<NoiseTcpStream> {
        let mut tcp = try!(TcpStream::connect(addr));
        let mut handshake = match (remote, local) {
            (None, Some(local)) => handshake::HandshakeXX::new(local),
            (None, None) => handshake::HandshakeNN::new(),
            _ => unimplemented!()
        };
        loop {
            try!(write_frame(&mut tcp, &handshake.send()[..]));
            match handshake.recv(&try!(read_frame(&mut tcp))[..]) {
                Ok(()) => (),
                Err(()) => return Err(io::Error::new(io::ErrorKind::Other, "Handshake failed"))
            }
            if handshake.done() {
                break
            }
        }
        let (client, server) = handshake.finish();
        Ok(NoiseTcpStream {
            tcp: tcp,
            local: client,
            remote: server
        })
    }
    pub fn accept(local: Option<session::KeyPair>,
                  remote: Option<session::PubKey>,
                  tcp: TcpStream) -> io::Result<NoiseTcpStream> {
        let mut tcp = tcp;
        let mut handshake = match (remote, local) {
            (None, Some(local)) => handshake::HandshakeXX::new(local),
            (None, None) => handshake::HandshakeNN::new(),
            _ => unimplemented!()
        };
        loop {
            match handshake.recv(&try!(read_frame(&mut tcp))[..]) {
                Ok(()) => (),
                Err(()) => return Err(io::Error::new(io::ErrorKind::Other, "Handshake failed"))
            }
            try!(write_frame(&mut tcp, &handshake.send()[..]));
            if handshake.done() {
                break
            }
        }
        let (client, server) = handshake.finish();
        Ok(NoiseTcpStream {
            tcp: tcp,
            local: server,
            remote: client
        })
    }

    pub fn send(&mut self, prologue: &[u8], msg: &[u8]) -> io::Result<()> {
        let buf = self.local.create(prologue, &[], msg);
        try!(write_frame(&mut self.tcp, &buf[..]));
        Ok(())
    }
    pub fn recv(&mut self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        match self.remote.consume(&try!(read_frame(&mut self.tcp))[..], &[]) {
            Ok(x) => Ok(x),
            Err(()) => Err(io::Error::new(io::ErrorKind::Other, "Failed to process message"))
        }
    }
}
