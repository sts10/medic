use medic::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let paranoid_mode: bool = read_mode_and_explain(&args);

    let choice = get_menu_choice(paranoid_mode);

    let passwords_file_path: Option<String> = if choice == 3 {
        println!(
            "I need a text file of SHA-1 hashes of passwords to check your password offline.\n"
        );
        println!("To download a copy of very large list of password hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords");
        println!("Choose the SHA-1 version, ordered by prevalence. Then extract/unzip it to get an even larger txt file.\n");
        println!("Enter file path of SHA-1 hashes to check:");

        Some(get_file_path().unwrap())
    } else {
        None
    };

    println!("\nEnter file path of your KeePass database\n(This can either be the .kdbx file or a CSV export of your database)");
    let mut keepass_db_file_path = get_file_path().unwrap();
    if keepass_db_file_path == "t" {
        keepass_db_file_path = "test-files/test_db.kdbx".to_string();
    }

    let entries: Option<Vec<Entry>> = if is_allowed_access_to_user_passwords(paranoid_mode) {
        Some(get_entries(&keepass_db_file_path, None))
    } else {
        println!("You're in Paranoid mode and you have an internet connection. I can't let you open a KeePass database in Paranoid mode if you are able to connect to the internet.");
        println!(
            "Please either restart this app not in Paranoid more or disconnect your internet."
        );
        None
    };
    // Make sure we have Some Entries!
    let entries: Vec<Entry> = match entries {
        Some(entries) => entries,
        None => return,
    };

    println!("\n================================================\n");
    if choice == 1 {
        check_for_and_display_weak_passwords(&entries);
    } else if choice == 2 {
        let digest_map = make_digest_map(&entries).unwrap();
        present_duplicated_entries(digest_map);
    } else if choice == 3 {
        match passwords_file_path {
            Some(file_path) => {
                let breached_entries = check_database_offline(&file_path, entries, true).unwrap();
                present_breached_entries(&breached_entries);
            }
            None => panic!("No passwords file found"),
        }
    } else if choice == 4 && !paranoid_mode {
        let breached_entries = check_database_online(&entries);
        present_breached_entries(&breached_entries);
    } else {
        println!("I didn't recognize that choice.");
        return;
    }
    println!("\n================================================\n");
}

fn get_menu_choice(paranoid_mode: bool) -> u32 {
    loop {
        println!();
        println!("To check your KeePass database's passwords, do you want to:\n");
        println!("==> 1. Check for weak passwords");
        println!("==> 2. Check for duplicate passwords (entirely offline)");
        println!("==> 3. Check OFFLINE for breached passwords: Give me a database of SHA-1 hashed passwords to check your KeePass database against");
        if !paranoid_mode {
            println!("==> 4. Check ONLINE for breached passwords: I will hash your passwords and send the first 5 characters of each hash over the internet to HaveIBeenPwned, in order to check if they've been breached.");
        }
        println!();
        let choice: u32 = match gets().unwrap().parse() {
            Ok(i) => i,
            Err(_e) => {
                println!("Please enter a number");
                continue;
            }
        };
        if choice > 0 && (!paranoid_mode && choice <= 4) || (paranoid_mode && choice <= 3) {
            return choice;
        } else {
            println!("Please choose a number from the menu");
        }
    }
}
