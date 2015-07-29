extern crate susurrus;
extern crate getopts;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate byteorder;

use susurrus::{session, noisebox, tcp};
use getopts::Options;
use std::env;
use std::io;
use std::io::{Read, Write};
use std::fs::OpenOptions;
use rustc_serialize::hex::{FromHex,ToHex};
use std::string::String;
use std::net::TcpListener;

macro_rules! make_fixed {
    ($t:ty, $n:expr, $v:expr) => ({
        let mut res : [$t; $n] = [0; $n];
        assert!($v.len() == $n);
        for i in 0..$n { res[i] = $v[i] }
        res
    })
}

fn print_usage(program: &str, opts: Options) {
    let mut brief = format!("Usage: {} <command> [options]", program);
    brief.push_str("\n\nCommands:\n");
    brief.push_str("    box         seals data in an encrypted box\n");
    brief.push_str("    unbox       unseals a box\n");
    brief.push_str("    keygen      generate a new keypair\n");
    brief.push_str("    pubkey      exract public key from keypair");
    brief.push_str("    tcpclient   start a simple TCP noise client");
    brief.push_str("    tcpserver   start a simple TCP noise server");
    print!("{}", opts.usage(&brief));
}

fn read_keypair<F:io::Read>(file: &mut F) -> io::Result<session::KeyPair> {
    let mut magic = [0u8;16];
    try!(file.read(&mut magic));
    if &magic[..] != b"noise255-secret:" {
        return Err(io::Error::new(io::ErrorKind::Other, "Missing magic"))
    }

    let mut pubkey_raw = [0u8; 64];
    try!(file.read(&mut pubkey_raw));
    let pubkey = match String::from_utf8_lossy(&pubkey_raw[..]).from_hex() {
        Ok(x) => x,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e))
    };
    let mut privkey_raw = [0u8; 64];
    try!(file.read(&mut privkey_raw));
    let privkey = match String::from_utf8_lossy(&privkey_raw[..]).from_hex() {
        Ok(x) => x,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e))
    };

    Ok(session::KeyPair { pubkey: session::PubKey(make_fixed!(u8, 32, pubkey)),
                          privkey: session::PrivKey(make_fixed!(u8, 32, privkey)) })
}

fn read_pubkey<F:io::Read>(file: &mut F) -> io::Result<session::PubKey> {
    let mut magic = [0u8;16];
    try!(file.read(&mut magic));
    if &magic[..] != b"noise255-public:" {
        return Err(io::Error::new(io::ErrorKind::Other, "Missing magic"))
    }

    let mut pubkey_raw = [0u8; 64];
    try!(file.read(&mut pubkey_raw));
    let pubkey = match String::from_utf8_lossy(&pubkey_raw[..]).from_hex() {
        Ok(x) => x,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e))
    };

    Ok(session::PubKey(make_fixed!(u8, 32, pubkey)))
}

fn tcpclient(local: Option<session::KeyPair>, remote: Option<session::PubKey>, addr: &str) -> io::Result<()> {
    let mut con = tcp::NoiseTcpStream::connect(local, remote, addr).unwrap();
    let mut stdin = io::stdin();
    loop {
        let mut line = String::new();
        try!(stdin.read_line(&mut line));
        try!(con.send(&[], line.as_bytes()));
    }
}

fn tcpserver(local: Option<session::KeyPair>, addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(&addr[..]).unwrap();
    for stream in listener.incoming() {
        let mut stream = try!(stream.and_then(|stream| tcp::NoiseTcpStream::accept(local.clone(), None, stream)));
        loop {
            match stream.recv() {
                Ok((prologue, payload)) => {
                    println!("prologue hex: {}", prologue.to_hex());
                    println!("prologue src: {}", &String::from_utf8_lossy(&prologue[..])[..]);
                    println!("payload hex: {}", payload.to_hex());
                    println!("payload src: {}", &String::from_utf8_lossy(&payload[..])[..]);
                }
                Err(e) => {
                    println!("{}", e);
                    break
                }
            }
        }
    }
    Ok(())
}

fn main() {
    sodiumoxide::init();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("a", "ascii", "ASCII armor encrypted result");
    opts.optopt("i", "input", "sets input file, defaults to stdin", "NAME");
    opts.optopt("o", "output", "set output file, defaults to stdout", "NAME");
    opts.optopt("r", "remote", "specifies file containing remote's public key", "NAME");
    opts.optopt("l", "local", "specifies file containing local key pair", "NAME");
    opts.optopt("t", "type", "specifies the box type to use (one of n, k, or x)", "TYPE");
    if args.len() < 2 {
        print_usage(&program, opts);
        return;
    }
    let command = args[1].clone();
    let matches = match opts.parse(&args[2..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    let mut output = match matches.opt_str("o") {
        Some(f) => match OpenOptions::new().write(true).create(true).open(&f) {
            Ok(x) => Box::new(x) as Box<io::Write>,
            Err(e) => return println!("Could not open output file {}: {}", f, e)
        },
        None => Box::new(io::stdout()) as Box<io::Write>
    };
    let mut input = match matches.opt_str("i") {
        Some(f) => match OpenOptions::new().read(true).open(&f) {
            Ok(x) => Box::new(x) as Box<io::Read>,
            Err(e) => return println!("Could not open input file {}: {}", f, e)
        },
        None => Box::new(io::stdin()) as Box<io::Read>
    };
    let remote = match matches.opt_str("r") {
        Some(f) => match OpenOptions::new().read(true).open(&f) {
            Ok(mut x) => match read_pubkey(&mut x) {
                Ok(x) => Some(x),
                Err(e) => return println!("Could not parse remote key file {}: {}", f, e)
            },
            Err(e) => return println!("Could not open remote key file {}: {}", f, e)
        },
        None => None
    };
    let local = match matches.opt_str("l") {
        Some(f) => match OpenOptions::new().read(true).open(&f) {
            Ok(mut x) => match read_keypair(&mut x) {
                Ok(x) => Some(x),
                Err(e) => return println!("Could not parse local key file {}: {}", f, e)
            },
            Err(e) => return println!("Could not open local key file {}: {}", f, e)
        },
        None => None
    };

    match &command[..] {
        "keygen" => {
            let kp = session::gen_keypair();
            output.write(&b"noise255-secret:"[..]).unwrap();
            output.write(&kp.pubkey.0[..].to_hex().as_bytes()).unwrap();
            output.write(&kp.privkey.0[..].to_hex().as_bytes()).unwrap();
        }
        "pubkey" => {
            let local = match local {
                Some(x) => x,
                None => return println!("Key pair must be specified to extract public key")
            };
            output.write(&b"noise255-public:"[..]).unwrap();
            output.write(&local.pubkey.0[..].to_hex().as_bytes()).unwrap();
        }
        "box" => {
            let mut buf = vec![];
            input.read_to_end(&mut buf).unwrap();
            let remote = match remote {
                Some(x) => x,
                None => return println!("Must specify remote key when encrypting")
            };
            enum BoxType {
                N, K, X
            }
            let boxtype = match matches.opt_str("t") {
                Some(x) => match x.as_ref() {
                    "n" => BoxType::N,
                    "k" => BoxType::K,
                    "x" => BoxType::X,
                    _ => return println!("Unrecognized box type {}", x),
                },
                None => if local.is_some() {
                    BoxType::X
                } else {
                    BoxType::N
                }
            };
            let res = match boxtype {
                BoxType::N => noisebox::BoxN::enbox(remote, &buf[..]),
                BoxType::K => noisebox::BoxK::enbox(local.unwrap(), remote, &buf[..]),
                BoxType::X => noisebox::BoxX::enbox(local.unwrap(), remote, &buf[..])
            };
            if matches.opt_present("a") {
                let mut out = String::new();
                out.push_str("noise255-message:");
                out.push_str(&res.to_hex()[..]);
                output.write_all(out.as_bytes()).unwrap();
            } else {
                output.write_all(&res[..]).unwrap();
            }
        }
        "unbox" => {
            let mut buf = vec![];
            input.read_to_end(&mut buf).unwrap();
            let local = match local {
                Some(x) => x,
                None => return println!("Must specify local key when decrypting")
            };
            let msg = if &buf[..17] == &b"noise255-message:"[..] {
                String::from_utf8_lossy(&buf[17..]).from_hex().unwrap()
            } else {
                buf
            };
            let result = match remote {
                Some(x) => noisebox::BoxK::unbox(x, local.clone(), &msg[..]),
                None => Err(())
            }.or(noisebox::BoxN::unbox(local.clone(), &msg[..]))
                .or(noisebox::BoxX::unbox(local, &msg[..]));
            match result {
                Ok(x) => match output.write_all(&x[..]) {
                    Ok(()) => (),
                    Err(e) => println!("Write failed: {:?}", e)
                },
                Err(e) => println!("Decryption failed: {:?}", e)
            }
        }
        "tcpclient" => {
            if matches.free.len() != 1 {
                println!("Address must be provided as free argument");
                return
            }
            match tcpclient(local, remote, &matches.free[0][..]) {
                Ok(()) => (),
                Err(x) => println!("{}", x)
            }
        }
        "tcpserver" => {
            if matches.free.len() > 1 {
                println!("Bind address must be provided as free argument");
                return
            }
            let addr = matches.free.get(0).map(|s| s.clone()).unwrap_or("0.0.0.0:8000".to_string());
            match tcpserver(local, &addr[..]) {
                Ok(()) => (),
                Err(x) => println!("{}", x)
            }
        }
        _ => print_usage(&program, opts)
    }
    output.flush().unwrap();
}
