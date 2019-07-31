# Medic

A Rust CLI that provides a variety of ways to check the "health" of a given KeePass database, including checking passwords against the Have I Been Pwned password list. 

**WARNING**: This software is a work in progress and still experimental. I would **NOT** use it with real KeePass databases or passwords just yet. 

[Read more about this project](https://sts10.github.io/2019/02/01/medic.html).

## What this tool does

Medic can check the passwords of a given KeePass database in four ways: 

1. Check passwords against the HaveIBeenPwned password database, via the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v2#PwnedPasswords)
2. Check passwords against a file of password hashes. This requires users to download a large list of SHA-1 hashes of breached or compromised passwords. I tailored it to work with the Pwned Passwords lists from HaveIBeenPwned, which anyone can download [here](https://haveibeenpwned.com/Passwords). Medic will then display a list of any passwords from the given KeePass database that also appear in the list of breached passwords.
3. Check for weak passwords, using [zxcvbn](https://github.com/dropbox/zxcvbn)
4. Check for duplicate passwords

If you're familiar with [1Password's Watchtower feature](https://support.1password.com/watchtower/), Medic aims to accomplish similar functionality for KeePass databases (with the additional benefit of optionally working entirely offline).

## Usage

```text
USAGE:
    medic [FLAGS] [OPTIONS] <KEEPASS DATABASE FILE>

FLAGS:
    -d, --duplicate    Check database for duplicate passwords
    -w, --weak         Check database for weak passwords
        --help         Prints help information
        --online       Check passwords against breached passwords online via the HaveIBeenPwned API. More info here:
                       https://www.troyhunt.com/ive-
                       just-launched-pwned-passwords-version-2/#cloudflareprivacyandkanonymity
    -V, --version      Prints version information
    -v, --verbose      Give verbose output

OPTIONS:
    -h, --hashfile <hash_file>    Provide password hash file to check database against. To download a copy of very large
                                  list of password hashes from HaveIBeenPwned, go to:
                                  https://haveibeenpwned.com/Passwords
    -k, --keyfile <keyfile>       Provide key file, if unlocking the KeePass databases requires one
    -o, --output <output>         Print results of health check to a file

ARGS:
    <KEEPASS DATABASE FILE>    KeePass database to check. Can either be a kdbx file or an exported CSV version of a
                               KeePass database.
```

### Examples

- `medic --online passwords.kdbx` checks the passwords of `passwords.kdbx` using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords. Prints report to the terminal.

- `medic --online -dw passwords.kdbx` checks the passwords of `passwords.kdbx` using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords. Prints report to the terminal.

- `medic --online -dw --output=./report.txt passwords.kdbx` checks the passwords of `passwords.kdbx` using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords. Prints report to the terminal. Prints result not to the terminal, but to a new text file `./report.txt`.

- `medic --online -w -k=test-files/test_key_file test-files/test_db.kdbx` checks the passwords of `test_db.kdbx` -- which requires key file `test_key_file` -- using the HaveIBeenPwned API, as well as looks for weak passwords. Prints results to terminal.

- `medic -h=../pwned-passwords-sha1-ordered-by-count-v4.txt my_db.kdbx` checks the passwords of `my_db.kdbx` against the hashes `../pwned-passwords-sha1-ordered-by-count-v4.txt`, which is a large text file of password hashes. Medic will display any of the accounts in the `my_db.kdbx` with passwords that appear in the list.

- `medic -dw passwords.kdbx` checks the passwords of `passwords.kdbx` for weak and duplicate passwords.

- `medic -dw passwords.kdbx --output=./password-report.txt` checks the passwords of `passwords.kdbx` for weak and duplicate passwords. Results are printed to a text file located at `./password-report.txt`.

- `medic -d -h=pwnedpasswords.txt kp_database_exported_csv_file.csv` checks an exported csv file against the hashes in `pwnedpasswords.txt`, as well as searches for duplicate passwords.

## Installation/Setup

1. [Install Rust](https://www.rust-lang.org/tools/install) if you haven't already
2. `cargo install --git https://github.com/sts10/medic`
3. Optional: If you'd like to check if any of your passwords have been breached _without_ sending any information about them over the internet, you'll need to [download the Pwned Passwords list](https://haveibeenpwned.com/Passwords), ideally via torrent\*. Choose the SHA-1 version, the one ordered by prevalence. You'll need about 35 GB of space free to do this. The torrent downloads a `.7z` compressed file. Double click it to extract it to a ~22 GB text file. That's what this program will need to work with.

\* If you're new to torrents, [Transmission](https://transmissionbt.com) is a decent choice for an application to download torrents, which apparently works on Mac and Windows. (Personally, on Kubuntu, I used [KTorrent](https://www.kde.org/applications/internet/ktorrent/).) Once you have Transmission or another torrent-handling application installed, click the green "torrent" button on [the Pwned Passwords site](https://haveibeenpwned.com/Passwords). Save the (very small) `.torrent` file to your computer, then open that file with your torrent-downloading software. You may have to click "OK" or "Start", but once you do you'll be (probably slowly) downloading hundreds of millions of hashed passwords.

## How I choose to use this tool 

1. [Download the PwnedPasswords list](https://haveibeenpwned.com/Passwords) in the SHA-1 format, ordered by prevalence (this text file will be about 11 GB compressed, 22GB extracted). 
2. Open your KeePass database in KeePassXC or whatever desktop app you use to open your database. 
3. Export your KeePass database to a CSV file (In KeePassXC: `Database` menu > "Export to CSV...") (Heads up, this file includes your passwords, so be careful). 
4. Lock your KeePass database.
5. Install Medic using instructions above.
6. Run Medic by entering the following command: `medic -h=pwnedpasswords.txt -dw <my-exported-database>.csv`. Note any compromised passwords and change them ASAP.
7. When finished, securely delete that exported CSV file. If on MacOS, run `srm <my-exported-database>.csv`. On Ubuntu-based Linux distributions, try `shred -ufv --iterations=60 <my-exported-database>.csv`. Your sensitive data should now be safely deleted, but feel free to securely delete Medic itself if so inclined.

## To do

1. Better error handling (especially if user gets CLI arguments wrong or is using an incompatible KDF)
2. Write more tests 
4. Offer real packaging / installation options?
5. Offer an option to check for _similar_ passwords (maybe using [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs)?)
6. Design/commission a logo?!

## Reference

- [Troy Hunt blog post about the password database](https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/)
- The Rust crate Medic uses to open and read KeePass databases: [keepass-rs](https://github.com/sseemayer/keepass-rs)

### Similar projects
- [A KeePass extension for checking against HaveIBeenPwned](https://github.com/andrew-schofield/keepass2-haveibeenpwned)
- [HIBPOfflineCheck](https://github.com/mihaifm/HIBPOfflineCheck) - A Keepass plugin that performs offline checks against the haveibeenpwned passwords file

### Useful projects in Rust 
- [password-check](https://github.com/davidhewitt/password-check)
- [rust-pwned-passwords](https://github.com/master-d/rust-pwned-passwords)
- [keepass-diff](https://github.com/Narigo/keepass-diff)

### The CLI crate I used

I used [structopt](https://github.com/TeXitoi/structopt).
