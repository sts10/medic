# Medic

A Rust CLI that provides a variety of ways to check the "health" of a given KeePass database, including checking passwords against the Have I Been Pwned password list. 

**WARNING**: This software is a work in progress and still experimental. I would **NOT** use it with real KeePass databases or passwords just yet. I wrote [a blog post about this project](https://sts10.github.io/2019/02/01/medic.html).

## What this does

Medic can check the passwords of a given KeePass database in four ways: 

1. Check passwords against the HaveIBeenPwned password database, via the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v2#PwnedPasswords)
2. Check passwords against a file of password hashes. This requires users to download a large list of SHA-1 hashes of breached or compromised passwords. I tailored it to work with the Pwned Passwords lists from HaveIBeenPwned, which anyone can download [here](https://haveibeenpwned.com/Passwords). Medic will then display a list of any passwords from the given KeePass database that also appear in the list of breached passwords.
3. Check for weak passwords, using [zxcvbn](https://github.com/dropbox/zxcvbn)
4. Check for duplicate passwords

## Usage

```text
USAGE:
    medic [FLAGS] [OPTIONS] <KEEPASS DATABASE FILE>

FLAGS:
    -c, --checks     Perform additional checks for weak and duplicate passwords.
    -d, --debug      Activate debug mode
        --help       Prints help information
    -o, --online     Set whether to check hashes online via the HaveIBeenPwned API
    -V, --version    Prints version information

OPTIONS:
    -h, --hashfile <hash_file>    Provide password hash file to check database against. To download a copy of very large
                                  list of password hashes from HaveIBeenPwned, go to:
                                  https://haveibeenpwned.com/Passwords
    -k, --keyfile <keyfile>       Provide key file, if unlocking the KeePass databases requires one

ARGS:
    <KEEPASS DATABASE FILE>    KeePass database to check. Can either be a kdbx file or an exported CSV version of a
                               KeePass database.
```

### Examples

- `cargo run --release -- -h=../hibp/pwned-passwords-sha1-ordered-by-count-v4.txt test_db.kdbx` checks the passwords of `test_db.kdbx` against the hashes `../hibp/pwned-passwords-sha1-ordered-by-count-v4.txt`, which is a large text file of password hashes. Medic will display any of the accounts in the `test_db.kdbx` with passwords that appear in the list.

- `cargo run --release -- -o -c test.kdbx` checks the passwords of `test.kdbx` using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords.

- `cargo run --release -- -o -c -k=test-files/test_key_file -d test-files/test_db.kdbx` checks the passwords of `test_db.kdbx` -- which requires key file `test_key_file` -- using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords. 

- `cargo run --release -- -c test.kdbx` checks the passwords of `test.kdbx` for weak and duplicate passwords.

- `cargo run --release -- -c -h=pwnedpasswords.txt exported_csv_file.csv` checks an exported csv file against the hashes in `pwnedpasswords.txt`, as well as searches for weak and/or duplicate passwords.

## Installation/Setup

1. [Install Rust](https://www.rust-lang.org/tools/install) if you haven't already
2. Clone down the repo
3. Optional: If you'd like to check if any of your passwords have been breached _without_ sending any information about them over the internet, you'll need to [download the Pwned Passwords list](https://haveibeenpwned.com/Passwords), ideally via torrent\*. Choose the SHA-1 version, the one ordered by prevalence. You'll need about 35 GB of space free to do this. The torrent downloads a `.7z` compressed file. Double click it to extract it to a ~22 GB text file. That's what this program will need to work with.

\* If you're new to torrents, [Transmission](https://transmissionbt.com) is a decent choice for an application to download torrents, which apparently works on Mac and Windows. (Personally, on Kubuntu, I used [KTorrent](https://www.kde.org/applications/internet/ktorrent/).) Once you have Transmission or another torrent-handling application installed, click the green "torrent" button on [the Pwned Passwords site](https://haveibeenpwned.com/Passwords). Save the (very small) `.torrent` file to your computer, then open that file with your torrent-downloading software. You may have to click "OK" or "Start", but once you do you'll be (probably slowly) downloading hundreds of millions of hashed passwords.

## Limitations 

Currently, this tool only works if your KeePass database uses the Key Derivation Function (KDF) called "AES-KDF (KDBX 3.1)". It cannot open KeePass databases that use either AES-KDF (KDBX 4) or Argon2. I believe this is a limitation of the otherwise amazing [keepass-rs crate](https://github.com/sseemayer/keepass-rs).

If you use either of these incompatible KDFs, you can still use this tool by either (a) switching your db to "AES-KDF (KDBX 3.1)" or (b) exporting your database to a CSV file (see below).

## How I choose to use this tool 

1. [Download the PwnedPasswords list](https://haveibeenpwned.com/Passwords) (11 GB compressed, 22GB extracted). 
2. Open your KeePass database in KeePassXC or whatever desktop app you use to open your database. 
3. Export your KeePass database to a CSV file (In KeePassXC: `Database` menu > "Export to CSV...") (Heads up, this file includes your passwords, so be careful). 
4. Lock your KeePass database.
5. Clone down this tool and set it up following the instructions above. 
6. Run Medic by entering the following command: `cargo run --release -- -h=pwnedpasswords.txt -c <my-exported-database>.csv`
7. When finished, securely delete that exported CSV file. If on MacOS, run `srm <file_name>.csv`. On Ubuntu-based Linux distross, try `shred -ufv --iterations=45 <file_name>.csv`. Your sensitive data should now be safely deleted, but feel free to securely delete Medic itself if so inclined.

## To do

1. Better error handling
2. Write more tests
3. Handle entries with blank passwords better
4. Offer an option to check for _similar_ passwords (maybe using [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs)?)
5. Design/commission a logo?!

## Reference

- [Troy Hunt blog post about the password database](https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/)

### Similar projects
- [A KeePass extension for checking against HaveIBeenPwned](https://github.com/andrew-schofield/keepass2-haveibeenpwned)
- [HIBPOfflineCheck](https://github.com/mihaifm/HIBPOfflineCheck) - A Keepass plugin that performs offline checks against the haveibeenpwned passwords file

### Useful projects in Rust 
- [password-check](https://github.com/davidhewitt/password-check)
- [rust-pwned-passwords](https://github.com/master-d/rust-pwned-passwords)
- [keepass-rs](https://github.com/sseemayer/keepass-rs)
- [keepass-diff](https://github.com/Narigo/keepass-diff)

### The CLI crate I used

I used [structopt](https://github.com/TeXitoi/structopt).
