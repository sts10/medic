extern crate keepass;
use keepass::db::NodeRef;
use keepass::error::DatabaseOpenError;
use keepass::Database;
use keepass::DatabaseKey;
use std::fs::File;
use std::io::prelude::Read;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Entry {
    pub title: String,
    pub url: String,
    pub username: String,
    pub pass: String,
    pub digest: String,
}

impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if !self.title.is_empty() {
            write!(f, "{} on {}", self.username, self.title)
        } else if self.title.is_empty() && !self.url.is_empty() {
            write!(f, "{} for {}", self.username, self.url)
        } else {
            write!(f, "{}", self.username)
        }
    }
}

fn unlock_keepass_database(
    path: PathBuf,
    db_pass: String,
    keyfile_path: Option<PathBuf>,
) -> Result<keepass::Database, DatabaseOpenError> {
    let mut db_file = match File::open(path) {
        Ok(db) => db,
        Err(e) => panic!("Error opening KeePass database file: {}", e),
    };

    let mut keyfile: Option<File> = match keyfile_path {
        Some(keyfile_path) => match File::open(keyfile_path) {
            Ok(keyfile) => Some(keyfile),
            Err(e) => panic!("Error opening specified keyfile: {}", e),
        },
        None => None,
    };

    Database::open(
        &mut db_file, // the database
        DatabaseKey {
            password: Some(&db_pass),                              // password
            keyfile: keyfile.as_mut().map(|f| f as &mut dyn Read), // keyfile
        },
    )
}

pub fn build_entries_from_keepass_db(
    file_path: PathBuf,
    db_pass: String,
    keyfile_path: Option<PathBuf>,
) -> Option<Vec<Entry>> {
    let mut entries: Vec<Entry> = vec![];

    println!("Attempting to unlock your KeePass database...");
    let db = match unlock_keepass_database(file_path, db_pass, keyfile_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!(
                "Error unlocking KeePass database: {}. No entries found. Aborting.",
                e
            );
            return None;
        }
    };

    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            NodeRef::Group(_g) => {
                // println!("Saw group '{}'", g.name);
            }
            NodeRef::Entry(e) => {
                let entry_password: &str = match e.get_password() {
                    Some(p) => p,
                    None => {
                        eprintln!(
                            "Error reading a password for entry titled: \"{}\", username: \"{}\", on site {}.",
                            e.get_title().unwrap_or("Unknown"),
                            e.get_username().unwrap_or("Unknown"),
                            e.get("URL").unwrap_or("Unknown"),
                        );
                        // return None;
                        continue;
                    }
                };

                let this_entry = Entry {
                    title: e.get_title().unwrap_or("").to_string(),
                    username: e.get_username().unwrap_or("").to_string(),
                    // url: e.get("URL").unwrap().to_string(),
                    url: e.get_url().unwrap_or("").to_string(),
                    // pass: e.get_password().unwrap().to_string(),
                    pass: entry_password.to_string(),
                    digest: sha1_smol::Sha1::from(entry_password)
                        .digest()
                        .to_string()
                        .to_uppercase(),
                };
                if !this_entry.pass.is_empty() {
                    entries.push(this_entry);
                }
            }
        }
    }
    println!("Successfully read KeePass database!");
    Some(entries)
}

pub fn build_entries_from_csv(file_path: PathBuf) -> Option<Vec<Entry>> {
    let mut entries: Vec<Entry> = vec![];

    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error reading CSV file: {}. Aborting.", e);
            return None;
        }
    };
    let mut rdr = csv::Reader::from_reader(file);
    // Loop over each record.
    for result in rdr.records() {
        let record = match result {
            Ok(rec) => rec,
            Err(e) => {
                eprintln!(
                    "Error reading a line of the specified CSV file: {}. Aborting.",
                    e
                );
                return None;
            }
        };

        if record.get(0) == Some("Group") && record.get(1) == Some("Title") {
            continue;
        }

        let entry_password: &str = match record.get(3) {
            Some(p) => p,
            None => {
                println!(
                    "Error reading a password for entry:\n{}, username {}, on site {}.\nAborting without finding any entries.",
                    record.get(1).unwrap_or("Unknown Title"),
                    record.get(2).unwrap_or("Unknown"),
                    record.get(4).unwrap_or("Unknown URL"),
                );
                return None;
            }
        };
        let this_entry = Entry {
            title: record.get(1).unwrap().to_string(),
            username: record.get(2).unwrap().to_string(),
            url: record.get(4).unwrap().to_string(),
            pass: entry_password.to_string(),
            digest: sha1_smol::Sha1::from(entry_password)
                .digest()
                .to_string()
                .to_uppercase(),
        };
        if !this_entry.pass.is_empty() {
            entries.push(this_entry);
        }
    }
    Some(entries)
}
