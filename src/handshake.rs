use session::*;

pub struct Handshake {
    session: Session,
    state: usize,
    descriptors: &'static [&'static [Descriptor]],
}

impl Handshake {
    pub fn new(local: Option<KeyPair>, remote: Option<PubKey>, descriptors: &'static [&'static [Descriptor]]) -> Handshake {
        Handshake {
            session: Session::new(local, remote),
            state: 0,
            descriptors: descriptors
        }
    }
    fn descriptor(&self) -> &'static [Descriptor] {
        self.descriptors[self.state]
    }
    fn next_state(&mut self) -> bool {
        self.state += 1;
        self.state >= self.descriptors.len()
    }

    pub fn send(&mut self) -> Vec<u8> {
        let desc = self.descriptor();
        let msg = self.session.create(&[], desc, &[]);
        self.next_state();
        msg
    }

    pub fn recv(&mut self, msg: &[u8]) -> Result<bool,()> {
        let desc = self.descriptor();
        try!(self.session.consume(msg, desc));
        Ok(self.next_state())
    }

    pub fn finish(mut self) -> (Session, Session) {
        let mut first = self.session.derive();
        let second = first.derive();
        (first, second)
    }
}

pub struct HandshakeNN;

impl HandshakeNN {
    pub fn new() -> Handshake {
        static DESCS: &'static [&'static [Descriptor]] = &[
            &[Descriptor::Ephemeral],
            &[Descriptor::Ephemeral, Descriptor::DHEE]
        ];
        Handshake::new(None, None, DESCS)
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

pub struct HandshakeXX;

impl HandshakeXX {
    pub fn new(local: KeyPair) -> Handshake {
        static DESCS: &'static [&'static [Descriptor]] = &[
            &[Descriptor::Ephemeral],
            &[Descriptor::Ephemeral, Descriptor::DHEE, Descriptor::Static, Descriptor::DHSE],
            &[Descriptor::Static, Descriptor::DHSE]
        ];
        Handshake::new(Some(local), None, DESCS)
    }
}

#[test]
fn test_handshakeXX() {
    let mut client = HandshakeXX::new(gen_keypair());
    let mut server = HandshakeXX::new(gen_keypair());

    server.recv(&client.send()[..]).unwrap();
    client.recv(&server.send()[..]).unwrap();
    server.recv(&client.send()[..]).unwrap();
    let (c1, c2) = client.finish();
    let (s1, s2) = server.finish();
    assert!(c1.k.unwrap().0 == s1.k.unwrap().0);
    assert!(c2.k.unwrap().0 == s2.k.unwrap().0);
    assert!(&c1.h.0[..] == &s1.h.0[..]);
    assert!(&c2.h.0[..] == &s2.h.0[..]);
}
