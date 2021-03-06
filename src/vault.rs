extern crate gpgme;
extern crate rand;


use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::exit;
use std::path::Path;

use gpgme::Data;
use gpgme::ops;
use rustc_serialize::json;

use self::rand::Rng;

#[derive(RustcDecodable, RustcEncodable)]
pub struct Credential {
    pub domain: String,
    pub password: String,
    pub username: String,
}

impl Credential {
    pub fn new(domain: &str, username: &str, password: &str) -> Credential {
        Credential {
            domain: domain.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}


fn open_file_for_writing(path: &str) -> File {
    return File::create(Path::new(path)).unwrap();
}

pub fn find_domain_in_credential_vec(vec: &Vec<Credential>, searchstr: &str) -> Option<Credential> {
    for credential in vec {
        if credential.domain == searchstr {
            return Some(Credential::new(&credential.domain,
                                        &credential.username,
                                        &credential.password));
        }
    }
    None
}

pub fn save_updated_pw_file(vec: &Vec<Credential>,
                            path: &str,
                            ctx: &mut gpgme::Context,
                            recipient: &str) {
    let key = ctx.find_key(recipient).unwrap();

    let mut encrypted = Data::new().unwrap();

    ctx.set_armor(true);

    let serialized_vector = json::encode(&vec).unwrap();

    let output = serialized_vector.into_bytes();
    let mut output_data = Data::from_bytes(&output).unwrap();

    match ctx.encrypt(Some(&key),
                      ops::EncryptFlags::empty(),
                      &mut output_data,
                      &mut encrypted) {
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


pub fn load_encrypted_file(path: &str) -> Data {
    match Data::load(&path) {
        Ok(input) => input,
        Err(err) => {
            writeln!(io::stderr(), "pwm: error reading '{}': {}", path, err);
            exit(1);
        }
    }
}

pub fn decrypt_data(ctx: &mut gpgme::Context, input: &mut Data, decrypted: &mut Data) {
    match ctx.decrypt(input, decrypted) {
        Ok(_) => (),
        Err(err) => {
            writeln!(io::stderr(), "pwm: decrypting failed: {}", err);
            exit(1);
        }
    }
}

pub fn spawn_gpgme_context() -> gpgme::Context {
    let proto = gpgme::PROTOCOL_OPENPGP;
    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(proto).unwrap();
    ctx
}

pub fn load_credentials(mut ctx: &mut gpgme::Context, path: &str) -> Vec<Credential> {
    let mut input = load_encrypted_file(&path);
    let mut decrypted = Data::new().unwrap();

    // Decrypt & Get JSON
    decrypt_data(&mut ctx, &mut input, &mut decrypted);
    let decrypted_string = decrypted.into_string().unwrap();
    let credentials: Vec<Credential> = json::decode(&decrypted_string).unwrap();
    credentials
}

pub fn gen_random_password() -> String {
    let random_string: String = rand::thread_rng()
    .gen_ascii_chars()
    .take(12)
    .collect();
    random_string
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn needle_in_haystack() {
        let tuples = [("domain.comisthis", "notthisdomain"),
                      ("uisce.ie", "iamapassword"),
                      ("domain.com", "domain!"),
                      ("whatsapassword.io", "omg")];

        let searchdomain = "domain.com";
        let correctanswer = "domain!";
        let username = "Thor";

        let mut credentials: Vec<Credential> = Vec::new();
        for combo in tuples.iter() {
            credentials.push(Credential::new(combo.0, username, combo.1));
        }

        assert_eq!(find_domain_in_credential_vec(&credentials, searchdomain).unwrap().password,
                   correctanswer);
    }
}