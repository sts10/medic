use medic::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let paranoid_mode: bool = read_mode_and_explain(&args);
    println!("paranoid mode is {}", paranoid_mode);

    let choice = get_menu_choice(paranoid_mode);

    let passwords_file_path = if choice == 3 {
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

    // not loving this rigamarole for paranoid mode...
    let entries: Option<Vec<Entry>> = if is_allowed_to_open_a_keepass_database(paranoid_mode) {
        let db_pass = rpassword::read_password_from_tty(Some(
            "Enter the password to your KeePass database: ",
        ))
        .unwrap();
        Some(get_entries_from_keepass_db(&keepass_db_file_path, db_pass))
    } else {
        println!("You're in Paranoid mode and you have an internet connection. I can't let you open a KeePass database in Paranoid mode if you are able to connect to the internet.");
        println!(
            "Please either restart this app not in Paranoid more or disconnect your internet."
        );
        None
    };

    let entries: Vec<Entry> = match entries {
        Some(entries) => entries,
        None => return,
    };

    println!("\n================= BEGIN REPORT ==================\n");
    if choice == 1 {
        check_for_and_display_weak_passwords(&entries);
    } else if choice == 2 {
        let digest_map = make_digest_map(&entries).unwrap();
        present_duplicated_entries(digest_map);
    } else if choice == 3 && !passwords_file_path.is_empty() {
        let breached_entries = check_database_offline(&passwords_file_path, entries, true).unwrap();
        present_breached_entries(&breached_entries);
    } else if choice == 4 && confirm_online_check() {
        let breached_entries = check_database_online(&entries);
        present_breached_entries(&breached_entries);
    } else {
        println!("I didn't recognize that choice.");
        return;
    }
    println!("\n================== END REPORT ==================\n ");
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
