#![allow(unused_must_use)]
#![allow(non_snake_case)]

extern crate gpgme;
extern crate getopts;
extern crate rustc_serialize;

mod vault;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;
use getopts::Matches;
use gpgme::Data;
use rustc_serialize::json;

use vault::Credential;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] FILENAME", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

#[cfg_attr(rustfmt, rustfmt_skip)]
fn process_opts() -> Matches {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("i", "", "First time init");
    opts.optflag("b", "", "Also print username in style username:password");
    opts.optopt("f", "", "Lookup password matching this string", "DOMAIN");
    opts.optopt("d", "", "Save new password - The domain of the password to save", "DOMAIN");
    opts.optopt("p", "", "The password to save", "Password");
    opts.optopt("l", "", "The location of the encrypted password file", "PATH");
    opts.optopt("r", "", "The recipient", "RECIPIENT");
    opts.optopt("u", "", "The Username", "USERNAME");

// Validate options
    let matches = match opts.parse(&args[1..]) {
        Ok(matches) => matches,
        Err(fail) => {
            print_usage(&program, &opts);
            writeln!(io::stderr(), "{}", fail);
            exit(1);
        }
    };

// Print Help Message
    if matches.opt_present("h") {
        print_usage(&program, &opts);
        exit(1);
    }

    return matches;
}

fn main() {
    // Process params
    let opts = process_opts();

    // Let's setup some stuff
    let path = opts.opt_str("l").unwrap();
    let proto = gpgme::PROTOCOL_OPENPGP;
    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(proto).unwrap();

    // Run first time init
    if opts.opt_present("i") {
        let recipient = opts.opt_str("r").unwrap();
        let empty_credentials = Vec::new();
        vault::save_updated_pw_file(&empty_credentials, &path, &mut ctx, &recipient);
        println!("Password Store Initialized");
        exit(0);
    }

    // Load
    let mut input = vault::load_encrypted_file(&path);
    let mut decrypted = Data::new().unwrap();

    // Decrypt & Get JSON
    vault::decrypt_data(&mut ctx, &mut input, &mut decrypted);
    let decrypted_string = decrypted.into_string().unwrap();
    let mut credentials: Vec<Credential> = json::decode(&decrypted_string).unwrap();

    // If requested, find matching password for a given key
    if opts.opt_present("f") {
        let credential = match vault::find_domain_in_credential_vec(&credentials, &opts.opt_str("f").unwrap()) {
            Some(credential) => credential,
            _ => { 
                writeln!(io::stderr(), "pwm: No such credential found");
                exit(1);
            }
        };
            
        if opts.opt_present("b") {
            println!("{}:{}", &credential.username, &credential.password);
        } else {
            println!("{}", &credential.password);
        }
    }

    // If requested, writeout updated file
    if opts.opt_present("d") {
        let domain = opts.opt_str("d").unwrap();
        let pw = opts.opt_str("p").unwrap();
        let mut un = "".to_string();

        if opts.opt_present("u") {
            un = opts.opt_str("u").unwrap();
        }

        let credential = Credential::new(&domain, &un, &pw);
        let recipient = opts.opt_str("r").unwrap();

        credentials.push(credential);
        vault::save_updated_pw_file(&credentials, &path, &mut ctx, &recipient);
        println!("Credential Stored");
        exit(0);
    }
}
