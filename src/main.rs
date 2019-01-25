extern crate indicatif;
extern crate keepass;
extern crate reqwest;
extern crate rpassword;
extern crate sha1;
extern crate zxcvbn;

use indicatif::{ProgressBar, ProgressStyle};
use keepass::{Database, Node, OpenDBError};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::str::FromStr;
use zxcvbn::zxcvbn;

fn main() {
    println!();
    println!("To check your KeePass database's passwords, do you want to:\n");
    println!("==> 1. Check ONLINE : I will hash your passwords and send the first 5 characters of each hash over the internet to HaveIBeenPwned, in order to check if they've been breached.");
    println!("==> 2. Check OFFLINE: Give me a database of SHA-1 hashed passwords to check your KeePass database against");
    println!("==> 3. Check for weak passwords");
    println!("==> 4. Check for duplicate passwords (entirely offline)");
    println!();
    let choice: u32 = ensure("Please try again.").unwrap();

    let passwords_file_path = if choice == 2 {
        println!(
            "I need a text file of SHA-1 hashes of passwords to check your password offline.\n"
        );
        println!("To download a copy of very large list of password hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords");
        println!("Choose the SHA-1 version, ordered by prevalence. Then extract/unzip it, revelaing an even larger txt file.\n");
        println!("Enter file path of SHA-1 hashes to check:");

        gets().unwrap()
    } else {
        "".to_string()
    };

    println!("\nEnter file path of your KeePass database file");
    let mut keepass_db_file_path = gets().unwrap();
    if keepass_db_file_path == "t" {
        keepass_db_file_path = "test-files/test_db.kdbx".to_string();
    }

    let db_pass =
        rpassword::read_password_from_tty(Some("Enter the password to your KeePass database: "))
            .unwrap();
    let entries = get_entries_from_keepass_db(&keepass_db_file_path, db_pass);

    println!("\n================= BEGIN REPORT ==================\n");
    if choice == 1 && confirm_online_check() {
        let breached_entries = check_database_online(&entries);
        present_breached_entries(&breached_entries);
    } else if choice == 2 && !passwords_file_path.is_empty() {
        let breached_entries = check_database_offline(&passwords_file_path, entries, true).unwrap();
        present_breached_entries(&breached_entries);
    } else if choice == 3 {
        check_for_and_display_weak_passwords(&entries);
    } else if choice == 4 {
        let digest_map = make_digest_map(&entries).unwrap();
        present_duplicated_entries(digest_map);
    } else {
        println!("I didn't recognize that choice.");
        return;
    }
    println!("\n================== END REPORT ==================\n ");
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

fn get_entries_from_keepass_db(file_path: &str, db_pass: String) -> Vec<Entry> {
    let mut entries: Vec<Entry> = vec![];

    // clean up user-inputted file path to standardize across operating systems/terminal emulators
    let file_path = file_path.trim_matches(|c| c == '\'' || c == ' ');

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
    println!("Successfully read KeePass database!");
    entries
}

fn present_breached_entries(breached_entries: &[Entry]) {
    for breached_entry in breached_entries {
        println!(
            "Oh no! I found your password for {} on {}",
            breached_entry.username, breached_entry.title
        );
    }
}

fn check_database_online(entries: &[Entry]) -> Vec<Entry> {
    let mut breached_entries: Vec<Entry> = Vec::new();
    for entry in entries {
        let appearances = check_password_online(&entry.pass);
        if appearances > 0 {
            breached_entries.push(entry.clone());
        }
    }
    breached_entries
}

fn confirm_online_check() -> bool {
    // Confirm that user for sure wants to check online
    println!("\n\nHeads up! I'll be sending the first 5 characters of the hashes of your passwords over the internet to HaveIBeenPwned. \nType allow to allow this");
    if gets().unwrap() == "allow" {
        println!("Cool, I'll check your KeePass passwords over the internet now...\n");
        true
    } else {
        false
    }
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
        let this_suffix = &line[..35];
        let this_number_of_matches = line[36..].parse::<usize>().unwrap();
        if this_suffix == suffix {
            return this_number_of_matches;
        }
    }
    0
}

fn check_database_offline(
    passwords_file_path: &str,
    entries: Vec<Entry>,
    progress_bar: bool,
) -> io::Result<Vec<Entry>> {
    let mut this_chunk = Vec::new();
    let mut breached_entries: Vec<Entry> = Vec::new();
    // let mut number_of_hashes_checked: usize;

    let f = match File::open(passwords_file_path.trim_matches(|c| c == '\'' || c == ' ')) {
        Ok(res) => res,
        Err(e) => return Err(e),
    };

    // times via `cargo test --release can_check_offline --no-run && time cargo test --release can_check_offline -- --nocapture`
    // let chunk_size = 1_000_000; // real 1m24.709s
    // let chunk_size = 20_000_000; // real 1m13.159s
    let chunk_size = 10_000_000; // real 1m14.613s

    // println!("attempting to count number of lines");
    let line_count = 550_000_000 as u64;
    // println!("Read line count as {}", line_count);

    let pb = ProgressBar::new((line_count / 100_000) as u64);
    if progress_bar {
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner} [{elapsed_precise}] [{bar:40}] ({eta})"),
            // .progress_chars("#>-"),
        );
    }

    let file = BufReader::new(&f);
    for line in file.lines() {
        this_chunk.push(line.unwrap());
        if this_chunk.len() > chunk_size {
            match check_this_chunk(&entries, &this_chunk) {
                Ok(mut vec_of_breached_entries) => {
                    breached_entries.append(&mut vec_of_breached_entries)
                }
                Err(_e) => eprintln!("found no breached entries in this chunk"),
            }
            // number_of_hashes_checked += chunk_size;
            if progress_bar {
                pb.inc((chunk_size / 100_000) as u64);
            }
            this_chunk.clear();
        }
    }
    if progress_bar {
        pb.finish_with_message("Done.");
    }
    Ok(breached_entries)
}

fn check_this_chunk(entries: &[Entry], chunk: &[String]) -> io::Result<Vec<Entry>> {
    let mut breached_entries = Vec::new();

    for line in chunk {
        let this_hash = &line[..40];

        for entry in entries {
            if this_hash == entry.digest {
                // println!(
                //     "Oh no! I found your password for {} on {}",
                //     entry.username, entry.title
                // );
                breached_entries.push(entry.clone());
            }
        }
    }
    Ok(breached_entries)
}

fn make_digest_map(entries: &[Entry]) -> io::Result<HashMap<String, Vec<Entry>>> {
    let mut digest_map: HashMap<String, Vec<Entry>> = HashMap::new();
    for entry in entries {
        digest_map
            .entry(entry.clone().digest)
            .and_modify(|vec| vec.push(entry.clone()))
            .or_insert([entry.clone()].to_vec());
    }

    Ok(digest_map)
}

fn present_duplicated_entries(digest_map: HashMap<String, Vec<Entry>>) {
    let mut has_duplicated_entries = false;
    for groups in digest_map.values() {
        if groups.len() > 1 {
            println!("The following entries have the same password:\n");
            for entry in groups {
                println!("{} for {}", entry.username, entry.title);
            }
            has_duplicated_entries = true;
        }
    }

    if has_duplicated_entries {
        println!("\nPassword re-use is bad. Change passwords until you have no duplicates.");
    } else {
        println!("\nGood job -- no password reuse detected!");
    }
}

fn check_for_and_display_weak_passwords(entries: &[Entry]) {
    for entry in entries {
        let estimate = zxcvbn(&entry.pass, &[&entry.title, &entry.username]).unwrap();
        if estimate.score < 4 {
            println!("--------------------------------");
            println!(
                "Your password for {} on {} is weak.",
                entry.username, entry.title
            );
            give_feedback(estimate.feedback);
        }
    }
}

fn give_feedback(feedback: Option<zxcvbn::feedback::Feedback>) {
    let spacer = "   ";
    match feedback {
        Some(feedback) => {
            if let Some(warning) = feedback.warning {
                println!("Warning: {}\n", warning);
            }
            println!("Suggestions:");
            for suggestion in feedback.suggestions {
                println!("{}- {}", spacer, suggestion)
            }
        }
        None => println!("No suggestions."),
    }
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

#[test]
fn can_check_online() {
    let keepass_db_file_path = "test-files/test_db.kdbx".to_string();
    let test_db_pass = "password".to_string();
    let entries = get_entries_from_keepass_db(&keepass_db_file_path, test_db_pass);

    let breached_entries = check_database_online(&entries);
    assert_eq!(breached_entries.len(), 3);
}

// you're going to want to run this test by running `cargo test --release`, else it's going to take
// a real long time
#[test]
fn can_check_offline() {
    let keepass_db_file_path = "test-files/test_db.kdbx".to_string();
    let test_db_pass = "password".to_string();
    let passwords_file_path =
        "/home/sschlinkert/code/hibp/pwned-passwords-sha1-ordered-by-count-v4.txt".to_string();

    let entries = get_entries_from_keepass_db(&keepass_db_file_path, test_db_pass);

    let breached_entries = check_database_offline(&passwords_file_path, entries, false).unwrap();
    assert_eq!(breached_entries.len(), 3);
}

#[test]
fn can_make_a_map_digest() {
    let keepass_db_file_path = "test-files/test_db.kdbx".to_string();
    let test_db_pass = "password".to_string();

    let entries = get_entries_from_keepass_db(&keepass_db_file_path, test_db_pass);
    let digest_map = make_digest_map(&entries).unwrap();

    let mut number_of_entries_with_duplicate_passwords = 0;
    for groups in digest_map.values() {
        if groups.len() > 1 {
            for _entry in groups {
                number_of_entries_with_duplicate_passwords += 1;
            }
        }
    }

    assert_eq!(number_of_entries_with_duplicate_passwords, 2);
}
