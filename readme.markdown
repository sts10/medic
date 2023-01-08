# Medic

A Rust CLI that provides a variety of ways to check the "health" of a given KeePass database, including checking passwords against the Have I Been Pwned password list. 

**WARNING**: I wrote this program mostly for personal use and to learn Rust. Use on real passwords at your own risk!

[Read more about this project](https://sts10.github.io/2019/02/01/medic.html).

I'll note here that [KeePassXC](https://keepassxc.org/), [as of version 2.6.0](https://keepassxc.org/blog/2020-07-07-2.6.0-released/), has a lot of the same features as Medic, some of which are accessible through its easy-to-use graphical interface. I understand that you can also use the KeePassXC CLI tool to check your database against an offline list of password hashed.

## What this tool does

Medic can check the passwords of a given KeePass database in four ways: 

1. Check passwords against the HaveIBeenPwned password database, via the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v2#PwnedPasswords)
2. Check passwords against a file of password hashes. This requires users to download a large list of SHA-1 hashes of breached or compromised passwords. I tailored it to work with the Pwned Passwords lists from HaveIBeenPwned, which anyone can download [here](https://haveibeenpwned.com/Passwords). Medic will then display a list of any passwords from the given KeePass database that also appear in the list of breached passwords.
3. Check for weak passwords, using [zxcvbn](https://github.com/dropbox/zxcvbn)
4. Check for duplicate passwords

If you're familiar with [1Password's Watchtower feature](https://support.1password.com/watchtower/), Medic aims to accomplish similar functionality for KeePass databases (with the additional benefit of optionally working entirely offline).

## Usage

```text
Usage: medic [OPTIONS] <KEEPASS DATABASE FILE>

Arguments:
  <KEEPASS DATABASE FILE>  KeePass database to check. Can either be a kdbx file or an exported CSV version of a KeePass database

Options:
      --debug                 Use debug mode, which, among other things, displayed received arguments and hides progress bar when checking passwords against a file of hashed passwords
  -k, --keyfile <KEYFILE>     Provide key file, if unlocking the KeePass databases requires one
      --online                Check passwords against breached passwords online via the HaveIBeenPwned API. More info here: https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/#cloudflareprivacyandkanonymity
  -a, --hashfile <HASH_FILE>  Provide file containing SHA-1 hashes of passwords to check database against. To download a copy of a very large list of password SHA-1 hashes from HaveIBeenPwned, go to: https://haveibeenpwned.com/Passwords
  -d, --duplicate             Check database for duplicate passwords
  -w, --weak                  Check database for weak passwords
  -o, --output <OUTPUT>       Print results of health check to a file
  -h, --help                  Print help information
  -V, --version               Print version information
```

### Examples

- `medic --online passwords.kdbx` checks the passwords of `passwords.kdbx` using the HaveIBeenPwned API. Prints report to the terminal.

- `medic --online -dw passwords.kdbx` checks the passwords of `passwords.kdbx` using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords. Prints report to the terminal.

- `medic --online -dw --output=./report.txt passwords.kdbx` checks the passwords of `passwords.kdbx` using the HaveIBeenPwned API, as well as looks for weak and duplicate passwords. Prints result not to the terminal, but to a new text file `./report.txt`.

- `medic --online -w -k=test-files/test_key_file test-files/test_db.kdbx` checks the passwords of `test_db.kdbx` -- which requires key file `test_key_file` -- using the HaveIBeenPwned API, as well as looks for weak passwords. Prints results to terminal.

- `medic -h=../pwned-passwords-sha1-ordered-by-count-v4.txt my_db.kdbx` checks the passwords of `my_db.kdbx` against the password hashes found in `../pwned-passwords-sha1-ordered-by-count-v4.txt`, which is a large text file of password hashes. Medic will display any of the accounts in the `my_db.kdbx` with passwords that appear in the list to the terminal.

- `medic -dw passwords.kdbx` checks the passwords of `passwords.kdbx` for weak and duplicate passwords.

- `medic -dw passwords.kdbx --output=./password-report.txt` checks the passwords of `passwords.kdbx` for weak and duplicate passwords. Results are printed to a text file located at `./password-report.txt`.

- `medic -d -h=pwnedpasswords.txt kp_database_exported_csv_file.csv` checks an exported csv file against the hashes in `pwnedpasswords.txt`, as well as searches for duplicate passwords.

## Installation/Setup

1. [Install Rust](https://www.rust-lang.org/tools/install) if you haven't already
2. Run: `cargo install --git https://github.com/sts10/medic --branch main` or for better performance decrypting AES KeePass databases (see below), run: `RUSTFLAGS='-C target-cpu=native' cargo install --git https://github.com/sts10/medic --branch main`. See [keepass-rs documentation](https://github.com/sseemayer/keepass-rs#installation) for more optimizations.
3. Optional: If you'd like to check if any of your passwords have been breached _without_ sending any information about them over the internet, you'll need to [download the Pwned Passwords list](https://haveibeenpwned.com/Passwords), ideally via torrent (see below). Choose the SHA-1 version, the one ordered by prevalence. You'll need about 35 GB of space free (in total) to do this. The torrent downloads a `.7z` compressed file. Double click it to extract it to a ~22 GB text file. That's what this program will need to work with.

### Dependencies

On Debian-based distros like Ubuntu, Medic may require libssl-dev. Install with: `sudo apt-get install libssl-dev`.

### Downloading breached passwords from HaveIBeenPwned via torrent

If you're new to torrents, [Transmission](https://transmissionbt.com) is a decent choice for an application to download torrents, which apparently works on Mac and Windows. (Personally, on Kubuntu, I used [KTorrent](https://www.kde.org/applications/internet/ktorrent/).) Once you have Transmission or another torrent-handling application installed, click the green "torrent" button on [the Pwned Passwords site](https://haveibeenpwned.com/Passwords). Save the (very small) `.torrent` file to your computer, then open that file with your torrent-downloading software. You may have to click "OK" or "Start", but once you do you'll be (probably slowly) downloading hundreds of millions of hashed passwords.

## A note on KeePass databases that use an AES KDF (key derivation function)

By default, if your KeePass database uses an _AES_ KDF (key derivation function) Medic will not use your CPU to decrypt your KeePass database. That means that if your databases is locked with a high number of AES key transformation rounds, it will take a while for Medic to open your database. 

To solve this, either switch your database's KDF from "AES-KDF" to "Argon2", or install Medic by running this command: `RUSTFLAGS='-C target-cpu=native' cargo install --git https://github.com/sts10/medic --branch main`. If you've already installed Medic without the RUSTFLAG, try running `RUSTFLAGS='-C target-cpu=native' cargo install --force --git https://github.com/sts10/medic --branch main`

More info [here](https://github.com/sseemayer/keepass-rs/issues/15#issuecomment-543615390) and [here](https://docs.rs/aes/0.3.2/aes/).

## How I choose to use this tool 

1. [Download the PwnedPasswords list](https://haveibeenpwned.com/Passwords) in the SHA-1 format, ordered by prevalence (this text file will be about 11 GB compressed, 22GB extracted). 
2. Open your KeePass database in KeePassXC or whatever desktop app you use to open your database. 
3. Export your KeePass database to a CSV file (In KeePassXC: `Database` menu > "Export to CSV...") (Heads up, this file includes your passwords, so be careful). 
4. Lock your KeePass database.
5. Install Medic using instructions above.
6. Run Medic by entering the following command: `medic -h=pwnedpasswords.txt -dw <my-exported-database>.csv`. Note any compromised passwords and change them ASAP.
7. When finished, securely delete that exported CSV file. If on MacOS, run `srm <my-exported-database>.csv`. On Ubuntu-based Linux distributions, try `shred -ufv --iterations=60 <my-exported-database>.csv`. Your sensitive data should now be safely deleted, but feel free to securely delete Medic itself if so inclined.

## Running tests

`cargo test --release`, though you'll need a file with a list of hashed passwords to pass one of the tests. 

Note that all test databases passwords are `password`.

## Checking for security vulnerabilities in Medic's dependencies

You can programmatically check Medic's dependencies for security vulnerabilities with [cargo audit](https://github.com/RustSec/cargo-audit). 

If you find vulnerabilities that concerns you, you can attempt to update the offending dependent crate yourself in the `Cargo.toml` file. Also, please open an issue on this repo.

## To do

See Issues on GitHub for more, but here are some broad ideas:

- [ ] Better error handling (especially if user gets CLI arguments wrong or is using an incompatible KDF)
- [ ] Write more tests 
- [ ] Have the program be able to use multiple threads
- [ ] Offer real packaging / installation options?
- [ ] Offer an option to check for _similar_ passwords (maybe using [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs)?)
- [ ] Design/commission a logo?!

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
