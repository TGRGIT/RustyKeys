#![allow(unused_must_use)]
#![allow(unused_variables)]

extern crate gpgme;
extern crate getopts;
extern crate serde;
extern crate serde_json;

use std::env;
use std::io;
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;
use std::path::Path;

use getopts::Options;
use getopts::Matches;
use gpgme::Data;
use gpgme::ops;
use serde_json::Value;

struct UnPwCombo{
    domain : String,
    password : String
}

impl UnPwCombo {
    fn new(domain: &str, password: &str) -> UnPwCombo {
        UnPwCombo {
            domain: domain.to_string(),
            password: password.to_string()
        }
    }

    fn get_json_str(&self) -> String {
        return format!("\"{}\": \"{}\"", self.domain, self.password);
    }
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] FILENAME", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

fn process_opts() -> Matches {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("i", "", "First time init");
    opts.optopt("f", "", "Lookup password matching this string", "DOMAIN");
    opts.optopt("d", "", "Save new password - The domain of the password to save", "DOMAIN");
    opts.optopt("p", "", "The password to save", "Password");
    opts.optopt("l", "", "The location of the encrypted password file", "PATH");
    opts.optopt("r", "", "The recipient", "RECIPIENT");
    
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

fn open_file_for_writing(path: &str) -> File {
    return File::create(Path::new(path)).unwrap();
}

fn load_encrypted_file(path: &str) -> Data {
    match Data::load(&path) {
        Ok(input) => input,
        Err(err) => {
            writeln!(io::stderr(), "pwm: error reading '{}': {}", path, err);
            exit(1);
        }
    } 
}

fn decrypt_data (ctx: &mut gpgme::Context, input: &mut Data, decrypted: &mut Data){
    match ctx.decrypt(input, decrypted){
        Ok(_) => (),
        Err(err) => {
            writeln!(io::stderr(), "pwm: decrypting failed: {}", err);
            exit(1);
        }
    }
}


fn gen_json_from_vec(vec: &Vec<UnPwCombo>) -> String {
    let start_json_str = "{";
    let end_json_str = "}";
    let mut json_str = "".to_string();

    for combo in vec {
        if json_str == "" {
            json_str = combo.get_json_str();
        }else{
            json_str = format!("{},{}", &json_str, &combo.get_json_str()); 
        }
    } 

    return start_json_str.to_string() + &json_str + &end_json_str;
}

fn find_key_in_unpwcombo_vec(vec: &Vec<UnPwCombo>, searchstr : &str) -> String {
    for combo in vec {
        if combo.domain == searchstr {
            let x = &combo.password;
            return x.to_string();
        }
    } 

    writeln!(io::stderr(), "pwm: No such password");
    exit(1);
}

fn save_updated_pw_file(vec: &Vec<UnPwCombo>, path : &str, ctx: &mut gpgme::Context, recipient: &str) {
    let key = ctx.find_key(recipient).unwrap();

    let mut encrypted = Data::new().unwrap();

    ctx.set_armor(true);

    let output = gen_json_from_vec(&vec).into_bytes();
    let mut output_data = Data::from_bytes(&output).unwrap();

    match ctx.encrypt(Some(&key), ops::EncryptFlags::empty(), &mut output_data, &mut encrypted) {
        Ok(..) => (),
        Err(err) => {
            writeln!(io::stderr(), "encrypting failed: {}", err);
            exit(1);
        }
    }

    let encrypted_string = encrypted.into_string().unwrap();

    let mut f = open_file_for_writing(&path);

    f.write_all(&format!("{}", &encrypted_string).into_bytes());
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
        let combos = Vec::new();
        save_updated_pw_file(&combos, &path, &mut ctx, &recipient);
        println!("Password Store Initialized");
        exit(0);
    }

    // Load
    let mut input = load_encrypted_file(&path);
    let mut decrypted = Data::new().unwrap();

    // Decrypt & Get JSON
    decrypt_data(&mut ctx, &mut input, &mut decrypted);
    let decrypted_string = decrypted.into_string().unwrap();
    let json: Value = serde_json::from_str(&decrypted_string).unwrap();

    // Lets get our kvps in order
    let mut combos = Vec::new();
    let json_obj = json.as_object().unwrap();

    for (key, value) in json_obj.iter() {
        let combo = UnPwCombo::new(&key, &value.as_string().unwrap());
        combos.push(combo);
    }

    // If requested, find matching password for a given key
    if opts.opt_present("f") {
        let pw = find_key_in_unpwcombo_vec(&combos, &opts.opt_str("f").unwrap());
        println!("{}", &pw);
        exit(0);
    }

    // If requested, writeout updated file
    if opts.opt_present("d") {
        let domain = opts.opt_str("d").unwrap();
        let pw = opts.opt_str("p").unwrap();
        let combo = UnPwCombo::new(&domain, &pw);
        let recipient = opts.opt_str("r").unwrap();

        combos.push(combo);
        save_updated_pw_file(&combos, &path, &mut ctx, &recipient);
        println!("Password Stored");
        exit(0);
    }
}