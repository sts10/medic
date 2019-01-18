extern crate keepass;
extern crate reqwest;
extern crate rpassword;
extern crate sha1;

use keepass::{Database, Node, OpenDBError};
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::str::FromStr;
// Securely read a password and query the Pwned Passwords API to
// determine if it's been breached ever.

fn main() {
    // let pass = rpassword::prompt_password_stdout("Password: ").unwrap();
    // eprintln!("pass is {}", pass);
    println!("Enter file path");
    let file_path = gets().unwrap();
    let passwords = get_passwords(file_path);
}

fn get_passwords(file_path: String) {
    println!("Made it here");

    let db_pass = rpassword::read_password_from_tty(Some("Enter the password to check: ")).unwrap();
    // Open KeePass database
    let db = File::open(std::path::Path::new("test-files/test_db.kdbx"))
        .map_err(|e| OpenDBError::Io(e))
        // .and_then(|mut db_file| Database::open(&mut db_file, "password"))
        .and_then(|mut db_file| Database::open(&mut db_file, &db_pass))
        .unwrap();

    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            Node::Group(g) => {
                println!("Saw group '{0}'", g.name);
            }
            Node::Entry(e) => {
                let title = e.get_title().unwrap();
                let user = e.get_username().unwrap();
                let pass = e.get_password().unwrap();
                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
            }
        }
    }
}

fn check_password(pass: String) -> usize {
    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    eprintln!("digest is {}", digest);
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let mut response = reqwest::get(&url).unwrap();

    let body = response.text().unwrap();

    eprintln!("body is {}", body);

    // Reponse is a series of lines like
    //
    //  suffix:N
    //
    // Where N is the number of times that password has appeared.
    //
    let mut number_of_matches: usize = 0;

    for line in body.lines() {
        let mut split = line.split(':');
        // if split.next().unwrap() == suffix {
        //     println!("{} matches found.", split.next().unwrap());
        //     return;
        // }
        if split.nth(1).unwrap() == suffix {
            number_of_matches = number_of_matches + 1;
        }
    }

    // println!("No matches found.");
    return number_of_matches;
}

fn gets() -> io::Result<String> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => Ok(input.trim_end_matches("\n").to_string()),
        Err(error) => Err(error),
    }
}
