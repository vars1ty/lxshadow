use pwhash::unix::crypt;
use std::{fs::read_to_string, io::Error};

/// Password salt and full hash from /etc/shadow.
struct Password {
    salt: String,
    hash: String,
}

/// Checks if the provided password for the given user, is the same as the assigned one
/// Panics if encrypting the password fails, or if parsing /etc/shadow properly fails.
pub fn is_eq(username: &str, password: &str, log_errors: bool) -> Result<Option<bool>, Error> {
    let passwd = get_shadow(username, log_errors)?;
    if passwd.is_none() {
        if log_errors {
            println!("lxshadow: Couldn't find the user salt/hash, returning None!")
        }

        return Ok(None);
    }

    let passwd = passwd.unwrap();
    let salt = passwd.salt;
    let hash = passwd.hash;
    Ok(Some(
        crypt(password, &salt).expect("lxshadow: Failed encrypting password!") == hash,
    ))
}

/// Gets the salt and password hash for the given user.
fn get_shadow(username: &str, verbose: bool) -> Result<Option<Password>, Error> {
    let shadow = read_to_string("/etc/shadow")?;
    if !shadow.contains(username) {
        if verbose {
            println!("lxshadow: Username wasn't found in /etc/shadow, returning None!")
        }

        return Ok(None);
    }

    for line in shadow.lines() {
        if line.contains('$') && line.len() >= 8 && line.starts_with(username) {
            let split: Vec<&str> = line.split('$').collect();
            let salt = split[..3].join("$").split(':').nth(1).unwrap().to_owned();
            let hash = line
                .split(&format!("{username}:"))
                .nth(1)
                .expect("Failed finding a hash!")
                .split(':')
                .next()
                .expect("Failed finding a valid hash!")
                .to_owned();
            return Ok(Some(Password { salt, hash }));
        }
    }

    if verbose {
        println!("lxshadow: Couldn't find the user salt/hash, returning None!")
    }

    Ok(None)
}
