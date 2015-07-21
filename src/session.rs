use sodiumoxide::crypto::onetimeauth::poly1305;
use sodiumoxide::crypto::hash::sha512;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305;
//use sodiumoxide::randombytes::randombytes;
use byteorder::{LittleEndian, WriteBytesExt};

macro_rules! make_fixed {
    ($t:ty, $n:expr, $v:expr) => ({
        let mut res : [$t; $n] = [0; $n];
        assert!($v.len() == $n);
        for i in 0..$n { res[i] = $v[i] }
        res
    })
}

macro_rules! concat_vec {
    ($x:expr, $($y:expr),+) => ({
        $x.iter() $(.chain($y.iter()))+ .cloned().collect::<Vec<u8>>()
    })
}

pub fn pad16(input: &[u8]) -> Vec<u8> {
    let mut out = input.iter().cloned().collect::<Vec<u8>>();
    for _ in (out.len() % 16)..16 {
        out.push(0);
    }
    out
}

pub const MAC_LEN: usize = 16;
pub const CV_LEN: usize = 48;
pub const H_LEN: usize = 64;
pub const DH_LEN: usize = 32;
// "Noise255" followed by 16 zeros
pub const SUITE_NAME: [u8; 24] = [0x4E, 0x6F, 0x69, 0x73, 0x65, 0x32, 0x35, 0x35,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> sha512::Digest {
    let nkey = if key.len() > sha512::HASHBYTES {
        sha512::hash(key).0
    } else {
        let mut arr = [0u8; sha512::HASHBYTES];
        for i in 0..key.len() { arr[i] = key[i] }
        arr
    };
    let o_pad = nkey.iter().map(|x| x^0x5c).collect::<Vec<u8>>();
    let i_pad = nkey.iter().map(|x| x^0x36).collect::<Vec<u8>>();

    let in1 : sha512::Digest = sha512::hash(&concat_vec!(i_pad, message)[..]);
    sha512::hash(&concat_vec!(o_pad, in1.0)[..])
}

pub fn getkey(key: &chacha20::Key, nonce: &chacha20::Nonce) -> chacha20::Key {
    chacha20::Key(make_fixed!(u8, chacha20::KEYBYTES, chacha20::stream(chacha20::KEYBYTES, nonce, key)))
}

pub fn kdf(key: &chacha20::Key, nonce: &chacha20::Nonce, input: &[u8]) -> chacha20::Key {
    chacha20::Key(make_fixed!(u8, 32, hmac_sha512(&getkey(key, nonce).0[..], input).0[..32]))
}

pub fn dh(privkey: &[u8; DH_LEN], pubkey: &[u8; DH_LEN]) -> [u8; DH_LEN] {
    curve25519::scalarmult(&curve25519::Scalar(*privkey), &curve25519::GroupElement(*pubkey)).0
}

pub struct NoiseBody {
    ciphertext: Vec<u8>,
    mac: poly1305::Tag
}

#[derive(Clone)]
pub struct PubKey(pub [u8; DH_LEN]);
#[derive(Clone)]
pub struct PrivKey(pub [u8; DH_LEN]);

#[derive(Clone)]
pub struct KeyPair {
    pub pubkey: PubKey,
    pub privkey: PrivKey
}

pub struct Session {
    pub s: Option<KeyPair>,
    e: Option<KeyPair>,
    pub rs: Option<PubKey>,
    re: Option<PubKey>,
    pub k: Option<chacha20::Key>,
    pub n: u64,
    pub h: sha512::Digest
}

pub enum Descriptor {
    Ephemeral,
    Static,
    DHSS,
    DHEE,
    DHSE,
    DHES
}

pub fn gen_keypair() -> KeyPair {
    let bkp = curve25519xsalsa20poly1305::gen_keypair();
    KeyPair {
        pubkey: PubKey((bkp.0).0),
        privkey: PrivKey((bkp.1).0)
    }
}

impl Session {
    pub fn new(local: Option<KeyPair>, remote: Option<PubKey>) -> Session {
        Session {
            s: local,
            e: None,
            rs: remote,
            re: None,
            k: None,
            n: 0,
            h: sha512::Digest([0u8; 64])
        }
    }

    pub fn get_nonce(&mut self) -> chacha20::Nonce {
        let mut n = vec![];
        n.write_u64::<LittleEndian>(self.n).unwrap();
        self.n += 1;
        chacha20::Nonce::from_slice(&n[..]).unwrap()
    }

    pub fn derive(&mut self) -> Session {
        let n = self.get_nonce();
        Session {
            s: self.s.clone(),
            e: None,
            rs: self.rs.clone(),
            re: None,
            k: match self.k {
                Some(ref k) => {
                    Some(getkey(&k, &n))
                },
                None => None
            },
            n: 0,
            h: self.h.clone()
        }
    }

    fn session_dh(&mut self, sender: &PrivKey, receiver: &PubKey) {
        let n = self.get_nonce();
        let k = self.k.clone().unwrap_or(chacha20::Key([0; 32]));
        self.k = Some(kdf(&k, &n, &dh(&sender.0, &receiver.0)[..]));
    }

    pub fn create(&mut self, prologue: &[u8], descriptors: &[Descriptor], payload: &[u8]) -> Vec<u8> {
        assert!(prologue.len() < 256);
        let mut buf = vec![];
        buf.push(prologue.len() as u8);
        buf.extend(prologue.iter().cloned());

        macro_rules! dh_branch {
            ($a:ident, $b:ident) => ({
                let $a = self.$a.clone().unwrap().privkey;
                let $b = self.$b.clone().unwrap();
                self.session_dh(&$a, &$b)
            })
        }

        for d in descriptors.iter() {
            match *d {
                Descriptor::Ephemeral => {
                    self.e = Some(gen_keypair());
                    buf.extend(self.e.clone().unwrap().pubkey.0.iter().cloned())
                },
                Descriptor::Static => {
                    let k = self.k.clone().unwrap();
                    let n = self.get_nonce();
                    let s = self.s.clone().unwrap().pubkey.0;
                    let a = concat_vec!(buf, self.h.0);
                    buf.extend(NoiseBody::encrypt(&k, &n, &a[..], &s[..])
                               .write().iter().cloned());
                },
                Descriptor::DHSS => dh_branch!(s, rs),
                Descriptor::DHEE => dh_branch!(e, re),
                Descriptor::DHSE => dh_branch!(s, re),
                Descriptor::DHES => dh_branch!(e, rs)
            }
        }
        let n = self.get_nonce();
        let a = concat_vec!(buf, self.h.0);
        match self.k {
            Some(ref k) => {
                buf.extend(NoiseBody::encrypt(&k, &n, &a[..], payload).write().iter().cloned());
            }
            None => buf.extend(payload.iter().cloned())
        }
        if descriptors.len() > 0 {
            self.h = sha512::hash(&concat_vec!(self.h.0, buf)[..]);
        }

        buf
    }

    pub fn consume(&mut self, data: &[u8], descriptors: &[Descriptor])
                   -> Result<(Vec<u8>, Vec<u8>), ()> {
        assert!(data.len() > 0);
        let plen = data[0] as usize;
        let prologue = data[1..plen+1].to_vec();
        let mut off = plen + 1;

        macro_rules! dh_branch {
            ($a:ident, $b:ident) => ({
                let $a = self.$a.clone().unwrap().privkey;
                let $b = self.$b.clone().unwrap();
                self.session_dh(&$a, &$b)
            })
        }

        for d in descriptors.iter() {
            match *d {
                Descriptor::Ephemeral => {
                    self.re = Some(PubKey(make_fixed!(u8, DH_LEN, data[off..off+DH_LEN])));
                    off += DH_LEN;
                },
                Descriptor::Static => {
                    let k = self.k.clone().unwrap();
                    let n = self.get_nonce();
                    let a = concat_vec!(data[..off], self.h.0);
                    self.rs = Some(PubKey(make_fixed!(u8, DH_LEN, try!(NoiseBody::read(&data[off..off+DH_LEN+MAC_LEN])
                                                                       .decrypt(&k, &n, &a[..])))));
                    off += DH_LEN + MAC_LEN;
                },
                Descriptor::DHSS => dh_branch!(s, rs),
                Descriptor::DHEE => dh_branch!(e, re),
                Descriptor::DHSE => dh_branch!(e, rs), // reversed because consuming instead of creating
                Descriptor::DHES => dh_branch!(s, re)
            }
        }

        let n = self.get_nonce();
        let a = concat_vec!(data[..off], self.h.0);
        let payload = match self.k {
            Some(ref k) =>
                try!(NoiseBody::read(&data[off..]).decrypt(&k, &n, &a[..])),
            None => data[off..].to_vec()
        };
        if descriptors.len() > 0 {
            self.h = sha512::hash(&concat_vec!(self.h.0, data)[..]);
        }

        Ok((prologue, payload))
    }
}

impl NoiseBody {
    pub fn read(buf: &[u8]) -> NoiseBody {
        NoiseBody {
            ciphertext: buf[..buf.len() - MAC_LEN].to_vec(),
            mac: poly1305::Tag(make_fixed!(u8, MAC_LEN, buf[buf.len() - MAC_LEN..]))
        }
    }

    pub fn write(&self) -> Vec<u8> {
        let mut out = self.ciphertext.clone();
        out.extend(self.mac.0.iter().cloned());
        out
    }

    pub fn encrypt(key: &chacha20::Key, nonce: &chacha20::Nonce, authtext: &[u8], plaintext: &[u8]) -> NoiseBody {
        let mut message = vec![0u8; 64];
        message.extend(plaintext.iter().cloned());

        let keystream = chacha20::stream_xor(&message[..], nonce, key);
        let mac_key = make_fixed!(u8, 32, keystream[..32]);
        // ignore 32..64
        let ciphertext = &keystream[64..];

        let mut to_be_authenticated = pad16(authtext);
        to_be_authenticated.extend(pad16(&ciphertext[..]).iter().cloned());
        to_be_authenticated.write_u64::<LittleEndian>(authtext.len() as u64).unwrap();
        to_be_authenticated.write_u64::<LittleEndian>(plaintext.len() as u64).unwrap();
        let mac = poly1305::authenticate(&to_be_authenticated[..], &poly1305::Key(mac_key));

        NoiseBody {
            ciphertext: ciphertext.to_vec(),
            mac: mac
        }
    }

    /* pub fn encrypt_padded(key: &chacha20::Key, nonce: &chacha20::Nonce, pad_len: usize, app_data: &[u8], authtext: &[u8]) -> NoiseBody {
        let mut plaintext = vec![];
        plaintext.extend(app_data.iter().cloned());
        for _ in 0..pad_len { plaintext.push(0); } // TODO: Random padding
        plaintext.write_u32::<LittleEndian>(pad_len as u32).unwrap();
        self.encrypt(&plaintext[..], authtext)
    }*/

    pub fn decrypt(&self, key: &chacha20::Key, nonce: &chacha20::Nonce, authtext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut input = vec![0u8; 64];
        input.extend(self.ciphertext.iter().cloned());

        let keystream = chacha20::stream_xor(&input[..], nonce, key);
        let mac_key = make_fixed!(u8, 32, keystream[..32]);
        // ignore 32..64
        let plaintext = &keystream[64..];

        let mut to_be_authenticated = pad16(authtext);
        to_be_authenticated.extend(pad16(&self.ciphertext[..]).iter().cloned());
        to_be_authenticated.write_u64::<LittleEndian>(authtext.len() as u64).unwrap();
        to_be_authenticated.write_u64::<LittleEndian>(plaintext.len() as u64).unwrap();

        if poly1305::verify(&self.mac, &to_be_authenticated[..], &poly1305::Key(mac_key)) {
            Ok(plaintext.to_vec())
        } else {
            Err(())
        }
    }
}

#[test]
fn test_encrypt() {
    let key = chacha20::gen_key();
    let nonce = chacha20::gen_nonce();
    let input = "hello, world";
    let auth = "test";
    let body = NoiseBody::encrypt(&key, &nonce, auth.as_bytes(), input.as_bytes());
    let res = body.decrypt(&key, &nonce, auth.as_bytes());
    match res {
        Ok(v) => assert!(&v[..] == input.as_bytes()),
        Err(_) => assert!(false)
    }
}
