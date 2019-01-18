# Medic

A Rust CLI that checks the passwords of a KeePass database against the Have I Been Pwned password list. 

Currently the tool pings [the Pwned Passwords API](https://haveibeenpwned.com/API/v2#PwnedPasswords), sending the first 5 characters of the SHA-1 hash of each of your passwords. The HIBP API returns a number of matches, at which point the tool iterates through looking for the full hash match. If it finds a match it display that information, as well as how many times that password appears in the database. 

However, once I successfully download that password list, which anyone can do [here](https://haveibeenpwned.com/Passwords), I hope to make this tool optionally work completely offline for increased security.

## Usage

### Setup 

1. [Install Rust](https://www.rust-lang.org/tools/install) if you haven't already
2. Clone down the repo
3. Once this tool works offline, you'll need to [download the Pwned Passwords list](https://haveibeenpwned.com/Passwords), ideally via torrent.

### Running the tool

1. While in the repo, run `cargo run` or `cargo run --release`
2. Choose whether to check your KeePass database's password offline or online.
3. Follow the subsequent instructions.

## Reference

- [Troy Hunt blog post about the password database](https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/)

### Similar projects
- [A KeePass extension for checking against HaveIBeenPwned](https://github.com/andrew-schofield/keepass2-haveibeenpwned)

### Useful projects in Rust 
- [password-check](https://github.com/davidhewitt/password-check)
- [rust-pwned-passwords](https://github.com/master-d/rust-pwned-passwords)
- [keepass-rs](https://github.com/sseemayer/keepass-rs)
- [keepass-diff](https://github.com/Narigo/keepass-diff)


