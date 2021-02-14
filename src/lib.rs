extern crate csv;
extern crate indicatif;
extern crate keepass;
extern crate reqwest;
extern crate rpassword;
extern crate sha1;
extern crate zxcvbn;

pub mod entries;
use crate::entries::Entry;
use entries::build_entries_from_csv;
use entries::build_entries_from_keepass_db;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use zxcvbn::zxcvbn;
// use zxcvbn::Entropy;
// use zxcvbn::ZxcvbnError;
// use std::io::prelude::*;

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

pub fn get_entries(file_path: PathBuf, keyfile_path: Option<PathBuf>) -> Option<Vec<Entry>> {
    let file_extension = match get_file_extension(&file_path) {
        Some(extension) => extension,
        None => {
            eprintln!("No file extension found");
            return None;
        }
    };

    match file_extension.as_str() {
        "kdbx" => {
            let db_pass: String = match rpassword::read_password_from_tty(Some(
                "Enter the password to your KeePass database: ",
            )) {
                Ok(password) => password,
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    return None;
                }
            };

            build_entries_from_keepass_db(file_path, db_pass, keyfile_path)
        }
        "csv" => build_entries_from_csv(file_path),
        _ => None,
    }
}

fn get_file_extension(file_path: &PathBuf) -> Option<String> {
    match file_path.extension().and_then(OsStr::to_str) {
        Some(extension) => Some(extension.to_lowercase()),
        None => None,
    }
}
pub fn present_breached_entries(
    breached_entries: &[Entry],
    output_dest: &Destination,
) -> std::io::Result<()> {
    if !breached_entries.is_empty() {
        write_to(
            output_dest,
            "The following entries have passwords contained in the list of breached passwords:",
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

pub fn check_database_online(entries: &[Entry]) -> reqwest::Result<Vec<Entry>> {
    let mut breached_entries: Vec<Entry> = Vec::new();
    for entry in entries {
        let appearances = check_password_online(&entry.pass)?;
        if appearances > 0 {
            breached_entries.push(entry.clone());
        }
    }
    Ok(breached_entries)
}

fn check_password_online(pass: &str) -> reqwest::Result<usize> {
    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let response = reqwest::blocking::get(&url)?;
    let body = response.text()?;

    // Reponse is a series of lines like
    //  suffix:N
    // Where N is the number of times that password has appeared.

    for line in body.lines() {
        let this_suffix = &line[..35];
        let this_number_of_matches = line[36..].parse::<usize>().unwrap_or(1); // if error parsing the number of matches, at least record one match
        if this_suffix == suffix {
            return Ok(this_number_of_matches);
        }
    }
    Ok(0)
}

pub fn check_database_offline(
    hash_file: PathBuf,
    entries: &[Entry],
    progress_bar_visibility: VisibilityPreference,
) -> io::Result<Vec<Entry>> {
    let mut this_chunk = Vec::new();
    let mut breached_entries: Vec<Entry> = Vec::new();

    let f = File::open(hash_file)?;
    let passwords_file_size = f.metadata()?.len() as usize;

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
        let this_line = line?[..40].to_string();
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

fn check_this_chunk(entries: &[Entry], chunk: &[String]) -> io::Result<Vec<Entry>> {
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
            "\nRe-using passwords for multiple accounts is potentially dangerous. Recommend you change passwords until you have no duplicates.\n--------------------------------\n",
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
        let estimate = match zxcvbn(&entry.pass, &[&entry.title, &entry.username]) {
            Ok(estimate) => estimate,
            Err(e) => panic!("Error getting password strength estimate: {}", e),
        };
        entry.pass.len();
        if estimate.score() < 4 {
            write_to(output_dest, format!("Your password for {} is weak.", entry))?;
            give_feedback(estimate.feedback(), output_dest)?;
            write_to(output_dest, "\n--------------------------------")?;
        }
    }
    Ok(())
}

fn give_feedback(
    feedback: &Option<zxcvbn::feedback::Feedback>,
    output_dest: &Destination,
) -> std::io::Result<()> {
    match feedback {
        Some(feedback) => {
            if let Some(warning) = feedback.warning() {
                write_to(output_dest, format!("Warning: {}\n", warning))?;
            }
            write_to(output_dest, "Suggestions:")?;
            for suggestion in feedback.suggestions() {
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
            match File::open(file_path) {
                Ok(f) => {
                    eprintln!("File where you want to write, {:?}, already exists. Would you like to overwrite? (y/N)", f);
                    if gets()? == "y" {
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
            let mut f = OpenOptions::new().append(true).open(file_path)?;
            writeln!(f, "{}", &output.into())
        }
        Destination::Terminal => {
            // println!("{}", &output);
            let stdout = io::stdout(); // get the global stdout entity
            let mut handle = stdout.lock(); // acquire a lock on it
            writeln!(handle, "{}", output.into())
        }
    }
}
