extern crate keepass;
use keepass::{Database, Node};
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
        if self.title != "" {
            write!(f, "{} on {}", self.username, self.title)
        } else if self.title == "" && self.url != "" {
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

pub fn build_entries_from_csv(file_path: PathBuf) -> Vec<Entry> {
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
