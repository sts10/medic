extern crate csv;
extern crate indicatif;
extern crate keepass;
extern crate reqwest;
extern crate rpassword;
extern crate sha1;
extern crate zxcvbn;

use indicatif::{ProgressBar, ProgressStyle};
use keepass::{Database, Node};
use std::collections::HashMap;
// use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::prelude::Read;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use zxcvbn::zxcvbn;

use std::fs::OpenOptions;
// use std::io::prelude::*;

#[derive(Debug, Clone)]
pub struct Entry {
    title: String,
    url: String,
    username: String,
    pass: String,
    digest: String,
}

// #[derive(Debug)]
// pub enum Destination<'a> {
//     Terminal,
//     FilePath(&'a str),
// }

#[derive(Debug)]
pub enum Destination {
    Terminal,
    FilePath(String),
}
#[derive(Debug, PartialEq)]
pub enum VisibilityPreference {
    Show,
    Hide,
}

impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.title != "" {
            write!(f, "{} on {}", self.username, self.title)
        } else if self.title == "" && self.url != "" {
            write!(f, "{} for {}", self.username, self.url)
        } else {
            write!(f, "{}", self.username)
        }
    }
}

pub fn get_entries(file_path: PathBuf, keyfile_path: Option<PathBuf>) -> Vec<Entry> {
    let file_extension = file_path.extension().unwrap().to_str().unwrap();

    let db_pass: Option<String> = if file_extension != "csv" {
        Some(
            rpassword::read_password_from_tty(Some(
                "Enter the password to your KeePass database: ",
            ))
            .unwrap(),
        )
    } else {
        None
    };

    if file_extension != "csv" && db_pass.is_some() {
        build_entries_from_keepass_db(file_path, db_pass.unwrap(), keyfile_path)
    } else {
        build_entries_from_csv(file_path)
    }
}

fn unlock_keepass_database(
    path: PathBuf,
    db_pass: String,
    keyfile_path: Option<PathBuf>,
) -> keepass::Database {
    let mut keyfile = keyfile_path.map(|kfp| File::open(kfp).unwrap());

    match Database::open(
        &mut File::open(path).unwrap(),               // the database
        Some(&db_pass),                               // password
        keyfile.as_mut().map(|f| f as &mut dyn Read), // keyfile
    ) {
        Ok(db) => db,
        Err(e) => {
            panic!("\nError opening database: {}", e);
        }
    }
}

pub fn build_entries_from_keepass_db(
    file_path: PathBuf,
    db_pass: String,
    keyfile_path: Option<PathBuf>,
) -> Vec<Entry> {
    let mut entries: Vec<Entry> = vec![];

    println!("Attempting to unlock your KeePass database...");
    let db = unlock_keepass_database(file_path, db_pass, keyfile_path);
    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            Node::GroupNode(_g) => {
                // println!("Saw group '{}'", g.name);
            }
            Node::EntryNode(e) => {
                let this_entry = Entry {
                    title: e.get_title().unwrap().to_string(),
                    username: e.get_username().unwrap().to_string(),
                    url: e.get("URL").unwrap().to_string(),
                    pass: e.get_password().unwrap().to_string(),
                    digest: sha1::Sha1::from(e.get_password().unwrap().to_string())
                        .digest()
                        .to_string()
                        .to_uppercase(),
                };
                if this_entry.pass != "" {
                    entries.push(this_entry);
                }
            }
        }
    }
    println!("Successfully read KeePass database!");
    entries
}

fn build_entries_from_csv(file_path: PathBuf) -> Vec<Entry> {
    let mut entries: Vec<Entry> = vec![];

    let file = File::open(file_path).unwrap();
    let mut rdr = csv::Reader::from_reader(file);
    // Loop over each record.
    for result in rdr.records() {
        // An error may occur, so abort the program in an unfriendly way.
        let record = result.expect("a CSV record");

        if record.get(0) == Some("Group") && record.get(1) == Some("Title") {
            continue;
        }

        let this_entry = Entry {
            title: record.get(1).unwrap().to_string(),
            username: record.get(2).unwrap().to_string(),
            url: record.get(4).unwrap().to_string(),
            pass: record.get(3).unwrap().to_string(),
            digest: sha1::Sha1::from(record.get(3).unwrap())
                .digest()
                .to_string()
                .to_uppercase(),
        };
        if this_entry.pass != "" {
            entries.push(this_entry);
        }
    }
    entries
}
pub fn present_breached_entries(
    breached_entries: &[Entry],
    output_dest: &Destination,
) -> std::io::Result<()> {
    if !breached_entries.is_empty() {
        write_to(
            output_dest,
            "The following entries have passwords on contained in the list of breached passwords:",
        )?;
        for breached_entry in breached_entries {
            write_to(output_dest, format!("   - {}", breached_entry))?;
        }
    } else {
        write_to(
            output_dest,
            "I didn't find any of your passwords on the breached passwords list",
        )?;
    }
    Ok(())
}

pub fn check_database_online(entries: &[Entry]) -> Vec<Entry> {
    let mut breached_entries: Vec<Entry> = Vec::new();
    for entry in entries {
        let appearances = check_password_online(&entry.pass);
        if appearances > 0 {
            breached_entries.push(entry.clone());
        }
    }
    breached_entries
}

pub fn _confirm_online_check() -> bool {
    // Confirm that user for sure wants to check online
    println!("\n\nHeads up! I'll be sending the first 5 characters of the hashes of your passwords over the internet to HaveIBeenPwned. \nType allow to allow this");
    if gets().unwrap() == "allow" {
        println!("Cool, I'll check your KeePass passwords over the internet now...\n");
        true
    } else {
        false
    }
}

pub fn check_password_online(pass: &str) -> usize {
    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let mut response = reqwest::get(&url).unwrap();
    let body = response.text().unwrap();

    // Reponse is a series of lines like
    //  suffix:N
    // Where N is the number of times that password has appeared.

    for line in body.lines() {
        let this_suffix = &line[..35];
        let this_number_of_matches = line[36..].parse::<usize>().unwrap();
        if this_suffix == suffix {
            return this_number_of_matches;
        }
    }
    0
}

pub fn check_database_offline(
    hash_file: PathBuf,
    entries: &[Entry],
    progress_bar_visibility: VisibilityPreference,
) -> io::Result<Vec<Entry>> {
    let mut this_chunk = Vec::new();
    let mut breached_entries: Vec<Entry> = Vec::new();

    let f = match File::open(hash_file) {
        Ok(res) => res,
        Err(e) => return Err(e),
    };
    let passwords_file_size = f.metadata().unwrap().len() as usize;

    // times via `cargo test --release can_check_offline --no-run && time cargo test --release can_check_offline -- --nocapture`
    // let chunk_size = 1_000_000_000; // real 1m6.354s
    let chunk_size = 500_000_000; // real 1m7.686s

    let pb = ProgressBar::new(passwords_file_size as u64);
    if progress_bar_visibility == VisibilityPreference::Show {
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner} [{elapsed_precise}] [{bar:40}] ({eta})"),
            // .progress_chars("#>-"),
        );
    }

    let file = BufReader::new(&f);
    for line in file.lines() {
        let this_line = line.unwrap()[..40].to_string();
        this_chunk.push(this_line);
        if this_chunk.len() * 48 > chunk_size {
            match check_this_chunk(&entries, &this_chunk) {
                Ok(mut vec_of_breached_entries) => {
                    breached_entries.append(&mut vec_of_breached_entries)
                }
                Err(_e) => eprintln!("found no breached entries in this chunk"),
            }
            if progress_bar_visibility == VisibilityPreference::Show {
                pb.inc(chunk_size as u64);
            }
            this_chunk.clear();
        }
    }
    if progress_bar_visibility == VisibilityPreference::Show {
        pb.finish_with_message("Done.");
    }
    Ok(breached_entries)
}

pub fn check_this_chunk(entries: &[Entry], chunk: &[String]) -> io::Result<Vec<Entry>> {
    let mut breached_entries = Vec::new();

    for line in chunk {
        let this_hash = &line[..40];

        for entry in entries {
            if this_hash == entry.digest {
                breached_entries.push(entry.clone());
            }
        }
    }
    Ok(breached_entries)
}

pub fn make_digest_map(entries: &[Entry]) -> io::Result<HashMap<String, Vec<Entry>>> {
    let mut digest_map: HashMap<String, Vec<Entry>> = HashMap::new();
    for entry in entries {
        digest_map
            .entry(entry.clone().digest)
            .and_modify(|vec| vec.push(entry.clone()))
            .or_insert_with(|| vec![entry.clone()]);
    }

    Ok(digest_map)
}

// Clippy told me "warning: parameter of type `HashMap` should be generalized over different hashers"
pub fn present_duplicated_entries<S: ::std::hash::BuildHasher>(
    digest_map: HashMap<String, Vec<Entry>, S>,
    output_dest: &Destination,
) -> std::io::Result<()> {
    let mut has_duplicated_entries = false;
    for group in digest_map.values() {
        if group.len() > 1 {
            write_to(
                output_dest,
                "The following entries have the same password:\n",
            )?;
            for entry in group {
                write_to(output_dest, format!("   - {}", entry))?;
            }
            has_duplicated_entries = true;
        }
    }

    if has_duplicated_entries {
        write_to(
            output_dest,
            "\nPassword re-use is bad. Change passwords until you have no duplicates.\n--------------------------------\n",
        )
    } else {
        write_to(output_dest, "\nGood job -- no password reuse detected!")
    }
}

pub fn check_for_and_display_weak_passwords(
    entries: &[Entry],
    output_dest: &Destination,
) -> std::io::Result<()> {
    write_to(output_dest, "\n--------------------------------")?;
    for entry in entries {
        let estimate = zxcvbn(&entry.pass, &[&entry.title, &entry.username]).unwrap();
        if estimate.score < 4 {
            write_to(output_dest, format!("Your password for {} is weak.", entry))?;
            give_feedback(estimate.feedback, output_dest)?;
            write_to(output_dest, "\n--------------------------------")?;
        }
    }
    Ok(())
}

fn give_feedback(
    feedback: Option<zxcvbn::feedback::Feedback>,
    output_dest: &Destination,
) -> std::io::Result<()> {
    match feedback {
        Some(feedback) => {
            if let Some(warning) = feedback.warning {
                write_to(output_dest, format!("Warning: {}\n", warning))?;
            }
            write_to(output_dest, "Suggestions:")?;
            for suggestion in feedback.suggestions {
                write_to(output_dest, format!("   - {}", suggestion))?;
            }
        }
        None => write_to(output_dest, "No suggestions.")?,
    }
    Ok(())
}

pub fn gets() -> io::Result<String> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => Ok(input.trim_end_matches('\n').to_string()),
        Err(error) => Err(error),
    }
}

pub fn create_file(dest: &Destination) -> std::io::Result<()> {
    match dest {
        Destination::FilePath(file_path) => {
            // let _f = OpenOptions::new().create(true).open(file_path).unwrap();
            match File::open(file_path) {
                Ok(f) => {
                    eprintln!("File where you want to write, {:?}, already exists. Would you like to overwrite? (y/N)", f);
                    if gets().unwrap() == "y" {
                        File::create(file_path)?;
                    } else {
                        panic!("OK, exiting");
                    }
                }
                Err(_e) => {
                    File::create(file_path)?;
                }
            }
            Ok(())
        }
        Destination::Terminal => Ok(()),
    }
}
pub fn write_to<StringLike: Into<String>>(
    dest: &Destination,
    output: StringLike,
) -> std::io::Result<()> {
    match dest {
        Destination::FilePath(file_path) => {
            let mut f = OpenOptions::new().append(true).open(file_path).unwrap();
            writeln!(f, "{}", &output.into())
            // Ok(())
        }
        Destination::Terminal => {
            // println!("{}", &output);
            let stdout = io::stdout(); // get the global stdout entity
            let mut handle = stdout.lock(); // acquire a lock on it
            writeln!(handle, "{}", output.into())
        }
    }
}
