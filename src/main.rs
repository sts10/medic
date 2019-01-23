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

fn main() {
    println!("To check your KeePass database's passwords, do you want to:");
    println!("  1. Check OFFLINE: Give me a database of SHA-1 hashed passwords?");
    println!("  2. Check ONLINE : Send the first 5 characters of your passwords' hashes over the internet to HaveIBeenPwned?");
    let choice: u32 = ensure("Please try again.").unwrap();

    let passwords_file_path = if choice == 1 {
        println!("Enter file path of hashed password to check against");
        gets().unwrap()
    } else {
        "".to_string()
    };

    println!("Enter file path of your KeePass database file");
    let mut keepass_db_file_path = gets().unwrap();
    if keepass_db_file_path == "t" {
        keepass_db_file_path = "test-files/test_db.kdbx".to_string();
    }
    let entries = get_entries_from_keepass_db(&keepass_db_file_path);

    if choice == 1 && !passwords_file_path.is_empty() {
        let bad_entries = chug_through(&passwords_file_path, entries).unwrap();
        for bad_entry in bad_entries {
            println!("Found a bad entry: {:?}", bad_entry);
        }
    } else {
        for entry in entries {
            let appearances = check_password_online(&entry.pass);

            if appearances > 0 {
                println!(
                    "Oh no! I found your password for {} on {} {} times before",
                    entry.username, entry.title, appearances
                );
            }
        }
    }
}

#[derive(Debug)]
struct Entry {
    title: String,
    username: String,
    pass: String,
    digest: String,
}

impl Clone for Entry {
    fn clone(&self) -> Entry {
        Entry {
            title: self.title.clone(),
            username: self.username.clone(),
            pass: self.pass.clone(),
            digest: self.digest.clone(),
        }
    }
}

fn get_entries_from_keepass_db(file_path: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = vec![];

    let db_pass =
        rpassword::read_password_from_tty(Some("Enter the password to your KeePass database: "))
            .unwrap();
    // Open KeePass database
    println!("Attempting to unlock your KeePass database...");
    let db = match File::open(std::path::Path::new(file_path))
        // .map_err(|e| OpenDBError::Io(e))
        .map_err(OpenDBError::Io)
        .and_then(|mut db_file| Database::open(&mut db_file, &db_pass))
    {
        Ok(db) => db,
        Err(e) => panic!("Error: {}", e),
    };

    println!("Reading your KeePass database...");
    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            Node::Group(_g) => {
                // println!("Saw group '{}'", g.name);
            }
            Node::Entry(e) => {
                let this_entry = Entry {
                    title: e.get_title().unwrap().to_string(),
                    username: e.get_username().unwrap().to_string(),
                    pass: e.get_password().unwrap().to_string(),
                    digest: sha1::Sha1::from(e.get_password().unwrap().to_string())
                        .digest()
                        .to_string()
                        .to_uppercase(),
                };
                entries.push(this_entry);
            }
        }
    }
    entries
}

fn check_password_online(pass: &str) -> usize {
    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let mut response = reqwest::get(&url).unwrap();

    let body = response.text().unwrap();
    // eprintln!("body is {}", body);

    // Reponse is a series of lines like
    //  suffix:N
    // Where N is the number of times that password has appeared.
    // let mut number_of_matches: usize = 0;

    for line in body.lines() {
        let this_suffix = split_and_vectorize(line, ":")[0];
        let this_number_of_matches = split_and_vectorize(line, ":")[1].parse::<usize>().unwrap();
        if this_suffix == suffix {
            return this_number_of_matches;
        }
    }
    0
}

fn chug_through(passwords_file_path: &str, entries: Vec<Entry>) -> io::Result<Vec<Entry>> {
    let mut this_chunk = Vec::new();
    let mut bad_entries: Vec<Entry> = Vec::new();
    let mut number_of_hashes_checked = 0;

    let f = match File::open(passwords_file_path.trim_matches(|c| c == '\'' || c == ' ')) {
        Ok(res) => res,
        Err(e) => return Err(e),
    };
    let file = BufReader::new(&f);
    for line in file.lines() {
        this_chunk.push(line.unwrap());
        if this_chunk.len() > 1_000_000 {
            match check_this_chunk(&entries, &this_chunk) {
                Ok(mut vec_of_bad_entries) => bad_entries.append(&mut vec_of_bad_entries),
                Err(_e) => eprintln!("found no bad entries in this chunk"),
            }
            number_of_hashes_checked += 1_000_000;
            println!("I've checked {} hashes", number_of_hashes_checked);
            this_chunk.clear();
        }
    }
    Ok(bad_entries)
}

fn check_this_chunk(entries: &[Entry], chunk: &[String]) -> io::Result<Vec<Entry>> {
    let mut bad_entries = Vec::new();

    for line in chunk {
        // let this_hash = split_and_vectorize(&line, ":")[0];
        let this_hash = &line[..40];

        for entry in entries {
            if this_hash == entry.digest {
                println!("found a bad entry: {:?}", entry);
                bad_entries.push(entry.clone());
            }
        }
    }
    Ok(bad_entries)
}

fn gets() -> io::Result<String> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => Ok(input.trim_end_matches("\n").to_string()),
        Err(error) => Err(error),
    }
}
fn ensure<T: FromStr>(try_again: &str) -> io::Result<T> {
    loop {
        let line = match gets() {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        match line.parse() {
            Ok(res) => return Ok(res),
            // otherwise, display inputted "try again" message
            // and continue the loop
            Err(_e) => {
                eprintln!("{}", try_again);
                continue;
            }
        };
    }
}
fn split_and_vectorize<'a>(string_to_split: &'a str, splitter: &str) -> Vec<&'a str> {
    let split = string_to_split.split(splitter);
    split.collect::<Vec<&str>>()
}
