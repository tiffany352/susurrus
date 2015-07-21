use session::*;

pub struct HandshakeNN {
    session: Session,
    state: usize
}

impl HandshakeNN {
    pub fn new() -> HandshakeNN {
        HandshakeNN {
            session: Session::new(None, None),
            state: 0
        }
    }

    fn descriptor(&self) -> &'static [Descriptor] {
        static DESCS: &'static [&'static [Descriptor]] = &[
            &[Descriptor::Ephemeral],
            &[Descriptor::Ephemeral, Descriptor::DHEE]
        ];
        DESCS[self.state]
    }

    pub fn send(&mut self) -> Vec<u8> {
        let desc = self.descriptor();
        let msg = self.session.create(&[], desc, &[]);
        self.state += 1;
        msg
    }

    pub fn recv(&mut self, msg: &[u8]) -> Result<bool,()> {
        let desc = self.descriptor();
        try!(self.session.consume(msg, desc));
        self.state += 1;
        Ok(self.state > 1)
    }

    pub fn finish(mut self) -> (Session, Session) {
        let mut first = self.session.derive();
        let second = first.derive();
        (first, second)
    }
}

#[test]
fn test_handshakeNN() {
    let mut client = HandshakeNN::new();
    let mut server = HandshakeNN::new();

    server.recv(&client.send()[..]).unwrap();
    client.recv(&server.send()[..]).unwrap();
    let (c1, c2) = client.finish();
    let (s1, s2) = server.finish();
    assert!(c1.k.unwrap().0 == s1.k.unwrap().0);
    assert!(c2.k.unwrap().0 == s2.k.unwrap().0);
    assert!(&c1.h.0[..] == &s1.h.0[..]);
    assert!(&c2.h.0[..] == &s2.h.0[..]);
}

/*
client flow:

let hs = HandshakeNN::new();
socket.send(hs.send());
hs.recv(socket.recv());
let (send, recv) = hs.finish();

server flow:

let hs = HandshakeNN::new();
hs.recv(socket.recv());
socket.send(hs.send());
let (recv, send) = hs.finish();
*/
