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

    for password in passwords {
        let appearances = check_password(&password);
        println!("the password {} was found {} times", password, appearances);
    }
}

fn get_passwords(file_path: String) -> Vec<String> {
    println!("Made it here");
    let mut entries: Vec<String> = [].to_vec();

    let db_pass = rpassword::read_password_from_tty(Some("Enter the database password: ")).unwrap();
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
                let pass = e.get_password().unwrap().to_string();
                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                entries.push(pass);
            }
        }
    }
    entries
}

fn check_password(pass: &str) -> usize {
    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    eprintln!("digest is {}", digest);
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let mut response = reqwest::get(&url).unwrap();

    let body = response.text().unwrap();
    // eprintln!("body is {}", body);

    // Reponse is a series of lines like
    //
    //  suffix:N
    //
    // Where N is the number of times that password has appeared.
    //
    let mut number_of_matches: usize = 0;

    for line in body.lines() {
        let this_suffix = split_and_vectorize(line, ":")[0];
        let this_number_of_matches = split_and_vectorize(line, ":")[1].parse::<usize>().unwrap();
        if this_suffix == suffix {
            number_of_matches = number_of_matches + this_number_of_matches;
        }
    }
    return number_of_matches;
}

fn gets() -> io::Result<String> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => Ok(input.trim_end_matches("\n").to_string()),
        Err(error) => Err(error),
    }
}

fn split_and_vectorize<'a>(string_to_split: &'a str, splitter: &str) -> Vec<&'a str> {
    let split = string_to_split.split(splitter);
    split.collect::<Vec<&str>>()
}
