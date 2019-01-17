extern crate reqwest;
extern crate rpassword;
extern crate sha1;

// Securely read a password and query the Pwned Passwords API to
// determine if it's been breached ever.

fn main() {
    let pass = rpassword::prompt_password_stdout("Password: ").unwrap();
    // dbg!(&pass);
    eprintln!("pass is {}", pass);

    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    eprintln!("digest is {}", digest);
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let mut response = reqwest::get(&url).unwrap();

    let body = response.text().unwrap();

    eprintln!("body is {}", body);

    // Reponse is a series of lines like
    //
    //  suffix:N
    //
    // Where N is the number of times that password has appeared.

    for line in body.lines() {
        let mut split = line.split(':');
        if split.next().unwrap() == suffix {
            println!("{} matches found.", split.next().unwrap());
            return;
        }
    }

    println!("No matches found.");
    return;
}
