extern crate keepass;
extern crate reqwest;
extern crate rpassword;
extern crate sha1;

use keepass::{Database, Node, OpenDBError};
use std::fs::File;
use std::io;
// Securely read a password and query the Pwned Passwords API to
// determine if it's been breached ever.

fn main() {
    // let pass = rpassword::prompt_password_stdout("Password: ").unwrap();
    // eprintln!("pass is {}", pass);
    println!("Enter file path (test-files/test_db.kdbx)");
    let mut file_path = gets().unwrap();
    if file_path == "t" {
        file_path = "test-files/test_db.kdbx".to_string();
    }
    let entries = get_entries(&file_path);

    for entry in entries {
        let appearances = check_password(&entry.pass);
        println!(
            "Your password for {} on {} was found {} times",
            entry.username, entry.title, appearances
        );
    }
}

#[derive(Debug)]
struct Entry {
    title: String,
    username: String,
    pass: String,
}

fn get_entries(file_path: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = vec![];

    let db_pass = rpassword::read_password_from_tty(Some("Enter the database password: ")).unwrap();
    // Open KeePass database
    let db = File::open(std::path::Path::new(file_path))
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
                let this_entry = Entry {
                    title: e.get_title().unwrap().to_string(),
                    username: e.get_username().unwrap().to_string(),
                    pass: e.get_password().unwrap().to_string(),
                };
                entries.push(this_entry);
            }
        }
    }
    entries
}

fn check_password(pass: &str) -> usize {
    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
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
