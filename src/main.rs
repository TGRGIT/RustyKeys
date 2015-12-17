#![allow(unused_must_use)]
#![allow(non_snake_case)]

extern crate gpgme;
extern crate getopts;
extern crate rustc_serialize;
extern crate rpassword;

mod vault;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;
use getopts::Matches;
use rpassword::read_password;

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
    opts.optflag("b", "", "For Search - Also print username in style username:password");
    opts.optflag("p", "", "Use Randomly generated password");
    opts.optopt("f", "", "Lookup password matching this string", "DOMAIN");
    opts.optopt("d", "", "Save new password - The domain of the password to save", "DOMAIN");
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
    let mut ctx = vault::spawn_gpgme_context();

    // Run first time init
    if opts.opt_present("i") {
        let recipient = opts.opt_str("r").unwrap();
        let empty_credentials = Vec::new();
        vault::save_updated_pw_file(&empty_credentials, &path, &mut ctx, &recipient);
        println!("Password Store Initialized");
        exit(0);
    }

    // Load
    let mut credentials = vault::load_credentials(&mut ctx, &path);

    // If requested, find matching password for a given key
    if opts.opt_present("f") {
        let credential = match vault::find_domain_in_credential_vec(&credentials,
                                                                    &opts.opt_str("f").unwrap()) {
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
        let pw : String;
        if opts.opt_present("p") {
            pw = vault::gen_random_password();
        }else{
            println!("Enter Secret Pasword Now;");
            pw = read_password().unwrap();   
        }
        let mut un = "".to_string();

        if opts.opt_present("u") {
            un = opts.opt_str("u").unwrap();
        }

        let credential = Credential::new(&domain, &un, &pw);
        let recipient = opts.opt_str("r").unwrap();

        credentials.push(credential);
        vault::save_updated_pw_file(&credentials, &path, &mut ctx, &recipient);
        if opts.opt_present("p") {
            println!("{}", pw);
        }else{
            println!("Credential Stored");
        }
        exit(0);
    }
}
