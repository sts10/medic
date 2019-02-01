# Medic

A Rust CLI that provides a variety of ways to check the "health" of a given KeePass database, including checking passwords against the Have I Been Pwned password list. 

**WARNING**: This software is a work in progress and still experimental. I would **NOT** use it with real KeePass databases or passwords just yet. I wrote [a blog post about this project](https://sts10.github.io/2019/02/01/medic.html).

**Medic provides four ways to check the "health" of a given KeePass database.** Here's the current menu:

```text
To check your KeePass database's passwords, do you want to:

==> 1. Check for weak passwords
==> 2. Check for duplicate passwords
==> 3. Check OFFLINE for breached passwords: Give me a database of SHA-1 hashed passwords to check your KeePass database against
==> 4. Check ONLINE for breached passwords: I will hash your passwords and send the first 5 characters of each hash over the internet to HaveIBeenPwned, in order to check if they've been breached.
```

Option 1 uses [zxcvbn](https://github.com/dropbox/zxcvbn) to find weak passwords in the given KeePass database. 

Option 2 simply finds entries which have the exact same password. (Password re-use is bad.)

Option 3 requires users to download a large list of SHA-1 hashes of breached or compromised passwords. I tailored it to work with the Pwned Passwords lists from HaveIBeenPwned, which anyone can download [here](https://haveibeenpwned.com/Passwords). Medic will then display a list of any passwords from the given KeePass database that also appear in the list of breached passwords.

Option 4 pings [the Pwned Passwords API](https://haveibeenpwned.com/API/v2#PwnedPasswords), sending the first 5 characters of the SHA-1 hash of each of your passwords. The HIBP API returns a number of matches, at which point the tool iterates through looking for the full hash match. If it finds a match it display that information, as well as how many times that password appears in the database. 

## Usage

### Setup 

1. [Install Rust](https://www.rust-lang.org/tools/install) if you haven't already
2. Clone down the repo
3. Optional: If you'd like to check if any of your passwords have been breached _without_ sending any information about them over the internet, you'll need to [download the Pwned Passwords list](https://haveibeenpwned.com/Passwords), ideally via torrent\*. Choose the SHA-1 version, the one ordered by prevalence. You'll need about 35 GB of space free to do this. The torrent downloads a `.7z` compressed file. Double click it to extract it to a ~22 GB text file. That's what this program will need to work with.

\* If you're new to torrents, [Transmission](https://transmissionbt.com) is a decent choice for an application to download torrents, which apparently works on Mac and Windows. (Personally, on Kubuntu, I used [KTorrent](https://www.kde.org/applications/internet/ktorrent/).) Once you have Transmission or another torrent-handling application installed, click the green "torrent" button on [the Pwned Passwords site](https://haveibeenpwned.com/Passwords). Save the (very small) `.torrent` file to your computer, then open that file with your torrent-downloading software. You may have to click "OK" or "Start", but once you do you'll be (probably slowly) downloading hundreds of millions of hashed passwords.

### Running the tool

1. While in the folder of this tool, run `cargo run --release` or `cargo run`
2. Make a choice from the presented menu (see above).
3. Follow the subsequent instructions.

### Paranoid mode

If you're worried about this tool sending any information over the internet without your knowledge, you can run it in "Paranoid mode". 

In "Paranoid mode", Medic can only open KeePass databases if your computer is **disconnected** from the internet. 

To run Medic in Paranoid mode, run `cargo run --release -- -p`. You'll be presented with a more-limited menu of options. Before making a menu choice, turn off your connection to the internet.

### How I chose to use this tool 

1. [Download the PwnedPasswords list](https://haveibeenpwned.com/Passwords) (11 GB compressed, 22GB extracted). 
2. Open your KeePass database in KeePassXC or whatever desktop app you use to open your database. 
3. Export your KeePass database to a CSV file (In KeePassXC: `Database` menu > "Export to CSv...") (Heads up, this file includes your passwords, so be careful). 
4. Lock your KeePass database.
5. Clone down this tool and set it up following the instructions above. 
6. Run Medic by entering the following command: `cargo run --release` 
7. Choose to perform the offline PwnedPasswords check. Optional: Search for weak or duplicate passwords. Copy and paste results in a new, local text document.
8. When finished, securely delete that exported CSV file. If on MacOS, run `srm <file_name>.csv`. On Ubuntu-based Linux distross, try `shred -ufv --iterations=45 <file_name>.csv`. Your sensitive data should now be safely deleted, but feel free to securely delete Medic itself if so inclined.

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


