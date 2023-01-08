use clap::Parser;
use medic::entries::Entry;
use medic::*;
use std::path::PathBuf;

/// Check the "health" of passwords in a KeePass database
#[derive(Parser, Debug)]
#[clap(name = "medic", version)]
struct Args {
    /// Use debug mode, which, among other things, displays received arguments and hides
    /// progress bar when checking passwords against a file of hashed passwords
    #[clap(long = "debug")]
    debug: bool,

    /// Provide key file, if unlocking the KeePass databases requires one
    #[clap(short = 'k', long = "keyfile")]
    keyfile: Option<PathBuf>,

    /// Check passwords against breached passwords online via the HaveIBeenPwned API. More info
    /// here:
    /// https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/#cloudflareprivacyandkanonymity
    #[clap(long = "online")]
    online: bool,

    /// Provide file containing SHA-1 hashes of passwords to check database against. To download a copy of a
    /// very large list of password SHA-1 hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords
    #[clap(short = 'a', long = "hashfile")]
    hash_file: Option<PathBuf>,

    /// Check database for duplicate passwords
    #[clap(short = 'd', long = "duplicate")]
    check_duplicate: bool,

    /// Check database for weak passwords
    #[clap(short = 'w', long = "weak")]
    check_weak: bool,

    /// Print results of health check to a file
    #[clap(short = 'o', long = "output")]
    output: Option<String>,

    /// KeePass database to check. Can either be a kdbx file or an exported CSV version of a
    /// KeePass database.
    #[clap(name = "KEEPASS DATABASE FILE")]
    keepass_db: PathBuf,
}

fn main() {
    let opt = Args::parse();
    if opt.debug {
        println!("Arguments received:\n{:?}", opt);
    }
    let keepass_db_file_path = opt.keepass_db;
    let hash_file: Option<PathBuf> = opt.hash_file;
    let keyfile: Option<PathBuf> = opt.keyfile;
    let check_online = opt.online;
    let progress_bar_visibility = if opt.debug {
        VisibilityPreference::Hide
    } else {
        VisibilityPreference::Show
    };
    let output_dest: Destination = match opt.output {
        Some(file_path) => Destination::FilePath(file_path),
        None => Destination::Terminal,
    };
    match &output_dest {
        Destination::FilePath(file_path) => {
            create_file(&Destination::FilePath(file_path.to_string()))
                .expect("Couldn't write to file");
        }
        Destination::Terminal => (),
    }

    if hash_file.is_none() && !check_online && !opt.check_duplicate && !opt.check_weak {
        eprintln!("Whoops! I have nothing the check against.");
        eprintln!("You must either:\n1. Provide a file with hashes of passwords to check against \nOR\n2. Use the --online flag to check your passwords online via HaveIBeenPwned API\nOR\n3. Use one or both of -d or -w flags to check for duplicate and/or weak passwords");
        eprintln!("Run --help for more information");
        return;
    }

    let entries: Vec<Entry> = match get_entries(keepass_db_file_path, keyfile) {
        Some(entries) => entries,
        None => panic!("Didn't find any entries in provided KeePass database"),
    };
    if opt.check_weak {
        match check_for_and_display_weak_passwords(&entries, &output_dest) {
            Ok(()) => (),
            Err(e) => panic!("Error checking for weak passwords!: {}", e),
        }
    }
    if opt.check_duplicate {
        let digest_map = match make_digest_map(&entries) {
            Ok(map) => map,
            Err(e) => panic!("Failed to check for duplicate passwords: {}", e),
        };
        present_duplicated_entries(digest_map, &output_dest)
            .expect("Error presenting duplicate passwords");
    }
    if let Some(hash_file) = hash_file {
        println!("Checking KeePass database against provided file of hashed passwords");
        let breached_entries =
            match check_database_offline(hash_file, &entries, progress_bar_visibility) {
                Ok(breached_entries) => breached_entries,
                Err(e) => panic!("Error checking database offline: {}", e),
            };

        present_breached_entries(&breached_entries, &output_dest)
            .expect("Error presenting breached entries");
    }
    if check_online {
        println!(
            "\nAre you sure you want to check the KeePass database against HaveIBeenPwned API? (y/N)"
        );
        match gets() {
            Ok(answer) => {
                if answer == "y" {
                    let breached_entries = match check_database_online(&entries) {
                        Ok(breached_entries) => breached_entries,
                        Err(e) => panic!("Error: {}", e),
                    };
                    present_breached_entries(&breached_entries, &output_dest)
                        .expect("Error presenting breached entries");
                }
            }
            Err(e) => eprintln!("Error reading your answer: {}", e),
        }
    }
}
