extern crate structopt;
use medic::*;
use std::path::PathBuf;
use structopt::StructOpt;

/// Medic
#[derive(StructOpt, Debug)]
#[structopt(name = "medic")]
struct Opt {
    /// Activate debug mode
    #[structopt(short = "d", long = "debug")]
    debug: bool,

    /// Provide key file, if unlocking the KeePass databases requires one
    #[structopt(short = "k", long = "keyfile", parse(from_os_str))]
    keyfile: Option<PathBuf>,

    /// Set whether to check hashes online via the HaveIBeenPwned API
    #[structopt(short = "o", long = "online")]
    online: bool,

    /// Provide password hash file to check database against. To download a copy of very large list of password hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords
    #[structopt(short = "h", long = "hashfile", parse(from_os_str))]
    hash_file: Option<PathBuf>,

    /// Perform additional checks for weak and duplicate passwords.
    #[structopt(short = "c", long = "checks")]
    additional_checks: bool,

    /// KeePass database to check
    #[structopt(name = "KEEPASS DATABASE FILE", parse(from_os_str))]
    keepass_db: PathBuf,
}
fn main() {
    let opt = Opt::from_args();
    if opt.debug {
        println!("{:?}", opt);
    }
    let keepass_db_file_path = opt.keepass_db;
    let hash_file: Option<PathBuf> = opt.hash_file;
    let keyfile: Option<PathBuf> = opt.keyfile;
    let check_online = opt.online;

    if hash_file == None && !check_online && !opt.additional_checks {
        println!("Whoops! I have nothing the check against");
        println!("You must either:\n1. Provide a hash file to check against \nOR\n2. Use the --online flag to check your passwords online via HaveIBeenPwned API");
        println!("Run --help for more information");
        return;
    }
    let entries: Option<Vec<Entry>> = Some(get_entries(keepass_db_file_path, keyfile));
    // Make sure we have Some Entries!
    let entries: Vec<Entry> = match entries {
        Some(entries) => entries,
        None => panic!("Didn't find any entries in provided KeePass database"),
    };

    if opt.additional_checks {
        check_for_and_display_weak_passwords(&entries);
        let digest_map = make_digest_map(&entries).unwrap();
        present_duplicated_entries(digest_map);
    }
    if let Some(file_path) = hash_file {
        println!("Checking KeePass database against provided hash file");
        let breached_entries = check_database_offline(file_path, &entries, true).unwrap();
        present_breached_entries(&breached_entries);
    }
    if check_online {
        println!(
            "\nAre you sure you want to check the KeePass database against HaveIBeenPwned API? (y/N)"
        );
        match gets() {
            Ok(answer) => {
                if answer == "y" {
                    let breached_entries = check_database_online(&entries);
                    present_breached_entries(&breached_entries);
                }
            }
            Err(e) => eprintln!("Error reading your answer: {}", e),
        }
    }
}
