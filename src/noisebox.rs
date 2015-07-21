use session::*;

pub struct BoxN;

impl BoxN {
    pub fn enbox(receiver: PubKey, pt: &[u8]) -> Vec<u8> {
        let mut s = Session::new(None, Some(receiver));
        s.create(&[], &[Descriptor::Ephemeral, Descriptor::DHES], pt)
    }

    pub fn unbox(receiver: KeyPair, ct: &[u8]) -> Result<Vec<u8>, ()> {
        let mut s = Session::new(Some(receiver), None);
        s.consume(ct, &[Descriptor::Ephemeral, Descriptor::DHES]).map(|(_,p)| p)
    }
}

pub fn pretty_print_hex(data: &[u8]) {
    let mut i = 0;
    for c in data.iter() {
        i += 1;
        print!("{:02x}", c);
        if i % 4 == 0 {
            print!(" ");
        }
        if i % 32 == 0 {
            print!("\n");
        }
    }
    if i % 32 != 0 {
        print!("\n");
    }
}

#[test]
fn test_boxn() {
    let msg = b"hello, world";
    let kp = gen_keypair();
    println!("\npubkey: ");
    pretty_print_hex(&kp.pubkey.0[..]);
    println!("privkey: ");
    pretty_print_hex(&kp.privkey.0[..]);
    println!("ciphertext: ");
    let ct = BoxN::enbox(kp.pubkey.clone(), msg);
    pretty_print_hex(&ct[..]);
    assert!(&msg[..] == &BoxN::unbox(kp, &ct[..]).ok().unwrap()[..]);
}

pub struct BoxK;

impl BoxK {
    pub fn enbox(sender: KeyPair, receiver: PubKey, pt: &[u8]) -> Vec<u8> {
        let mut s = Session::new(Some(sender), Some(receiver));
        s.create(&[], &[Descriptor::Ephemeral, Descriptor::DHES, Descriptor::DHSS], pt)
    }

    pub fn unbox(sender: PubKey, receiver: KeyPair, ct: &[u8]) -> Result<Vec<u8>, ()> {
        let mut s = Session::new(Some(receiver), Some(sender));
        s.consume(ct, &[Descriptor::Ephemeral, Descriptor::DHES, Descriptor::DHSS]).map(|(_,p)| p)
    }
}

#[test]
fn test_boxk() {
    let msg = b"hello, world";
    let skp = gen_keypair();
    let rkp = gen_keypair();
    println!("ciphertext: ");
    let ct = BoxK::enbox(skp.clone(), rkp.pubkey.clone(), msg);
    pretty_print_hex(&ct[..]);
    assert!(&msg[..] == &BoxK::unbox(skp.pubkey.clone(), rkp.clone(), &ct[..]).ok().unwrap()[..]);
}

pub struct BoxX;

impl BoxX {
    pub fn enbox(sender: KeyPair, receiver: PubKey, pt: &[u8]) -> Vec<u8> {
        let mut s = Session::new(Some(sender), Some(receiver));
        s.create(&[], &[Descriptor::Ephemeral, Descriptor::DHES, Descriptor::Static, Descriptor::DHSS], pt)
    }

    pub fn unbox(receiver: KeyPair, ct: &[u8]) -> Result<Vec<u8>, ()> {
        let mut s = Session::new(Some(receiver), None);
        s.consume(ct, &[Descriptor::Ephemeral, Descriptor::DHES, Descriptor::Static, Descriptor::DHSS]).map(|(_,p)| p)
    }
}

#[test]
fn test_boxx() {
    let msg = b"hello, world";
    let skp = gen_keypair();
    let rkp = gen_keypair();
    println!("ciphertext: ");
    let ct = BoxX::enbox(skp.clone(), rkp.pubkey.clone(), msg);
    pretty_print_hex(&ct[..]);
    assert!(&msg[..] == &BoxX::unbox(rkp.clone(), &ct[..]).ok().unwrap()[..]);
}
