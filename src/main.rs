extern crate structopt;
use medic::*;
use std::path::PathBuf;
use structopt::StructOpt;

/// Medic
#[derive(StructOpt, Debug)]
#[structopt(name = "medic")]
struct Opt {
    /// Give verbose output
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,

    /// Provide key file, if unlocking the KeePass databases requires one
    #[structopt(short = "k", long = "keyfile", parse(from_os_str))]
    keyfile: Option<PathBuf>,

    /// Check passwords against breached passwords online via the HaveIBeenPwned API. More info
    /// here:
    /// https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/#cloudflareprivacyandkanonymity
    #[structopt(long = "online")]
    online: bool,

    /// Provide password hash file to check database against. To download a copy of very large list of
    /// password hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords
    #[structopt(short = "h", long = "hashfile", parse(from_os_str))]
    hash_file: Option<PathBuf>,

    /// Check database for duplicate passwords
    #[structopt(short = "d", long = "duplicate")]
    check_duplicate: bool,

    /// Check database for weak passwords
    #[structopt(short = "w", long = "weak")]
    check_weak: bool,

    /// KeePass database to check. Can either be a kdbx file or an exported CSV version of a
    /// KeePass database.
    #[structopt(name = "KEEPASS DATABASE FILE", parse(from_os_str))]
    keepass_db: PathBuf,
}
fn main() {
    let opt = Opt::from_args();
    if opt.verbose {
        println!("{:?}", opt);
    }
    let keepass_db_file_path = opt.keepass_db;
    let hash_file: Option<PathBuf> = opt.hash_file;
    let keyfile: Option<PathBuf> = opt.keyfile;
    let check_online = opt.online;

    if hash_file == None && !check_online && !opt.check_duplicate && !opt.check_weak {
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

    if opt.check_weak {
        check_for_and_display_weak_passwords(&entries);
    }
    if opt.check_duplicate {
        let digest_map = make_digest_map(&entries).unwrap();
        present_duplicated_entries(digest_map);
    }
    if let Some(file_path) = hash_file {
        println!("Checking KeePass database against provided hash file");
        let breached_entries =
            check_database_offline(file_path, &entries, VisibilityPreference::Show).unwrap();
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
