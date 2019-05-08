extern crate structopt;
use medic::*;
// use std::env;
use std::path::PathBuf;
use structopt::StructOpt;

/// Medic
#[derive(StructOpt, Debug)]
#[structopt(name = "medic")]
struct Opt {
    // A flag, true if used in the command line. Note doc comment will
    // be used for the help message of the flag.
    /// Activate debug mode
    #[structopt(short = "d", long = "debug")]
    debug: bool,

    // The number of occurrences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: u8,

    /// Provide key file, if unlocking you KeePass databases requires one
    #[structopt(short = "k", long = "keyfile", parse(from_os_str))]
    keyfile: Option<PathBuf>,

    /// Set whether to check hashes online via the HaveIBeenPwned API
    #[structopt(short = "o", long = "online")]
    online: bool,

    /// Provide password hash file to check database against. To download a copy of very large list of password hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords
    #[structopt(short = "h", long = "hashfile", parse(from_os_str))]
    hash_file: Option<PathBuf>,

    /// Additional checks. "weak" to check for weak passwords; "duplicate" or "dup" to check for
    /// duplicate passwords.
    #[structopt(short = "c", long = "checks")]
    additional_checks: Vec<String>,

    /// KeePass database to check
    #[structopt(name = "KEEPASS DATABASE FILE", parse(from_os_str))]
    keepass_db: PathBuf,
}
fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    // let args: Vec<String> = env::args().collect();
    // let choice = get_menu_choice();

    // let keepass_db_file_path = opt['keepass_db'];
    let keepass_db_file_path = opt.keepass_db;
    let hash_file: Option<PathBuf> = opt.hash_file;
    let keyfile: Option<PathBuf> = opt.keyfile;
    let check_online = opt.online;
    // let additional_checks = opt.additional_checks;

    let entries: Option<Vec<Entry>> = Some(get_entries(keepass_db_file_path, keyfile));
    // Make sure we have Some Entries!
    let entries: Vec<Entry> = match entries {
        Some(entries) => entries,
        None => panic!("Didn't find any entries in provided KeePass database"),
    };

    for additional_check in opt.additional_checks {
        if additional_check == "weak" {
            check_for_and_display_weak_passwords(&entries);
        }
        if additional_check == "duplicate" || additional_check == "dup" {
            let digest_map = make_digest_map(&entries).unwrap();
            present_duplicated_entries(digest_map);
        }
    }
    match hash_file {
        Some(file_path) => {
            let breached_entries = check_database_offline(file_path, &entries, true).unwrap();
            present_breached_entries(&breached_entries);
        }
        None => (),
    }
    if check_online {
        let breached_entries = check_database_online(&entries);
        present_breached_entries(&breached_entries);
    }
}

fn _get_menu_choice() -> u32 {
    loop {
        println!();
        println!("To check your KeePass database's passwords, do you want to:\n");
        println!("==> 1. Check for weak passwords");
        println!("==> 2. Check for duplicate passwords");
        println!("==> 3. Check OFFLINE for breached passwords: Give me a database of SHA-1 hashed passwords to check your KeePass database against");
        println!("==> 4. Check ONLINE for breached passwords: I will hash your passwords and send the first 5 characters of each hash over the internet to HaveIBeenPwned, in order to check if they've been breached.");
        println!();
        let choice: u32 = match gets().unwrap().parse() {
            Ok(i) => i,
            Err(_e) => {
                println!("Please enter a number");
                continue;
            }
        };
        if choice > 0 && choice <= 4 {
            return choice;
        } else {
            println!("Please choose a number from the menu");
        }
    }
}
