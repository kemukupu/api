use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash a string with a random salt to be stored in the database.
/// Utilizes the argon2id algorithm
/// Followed best practices as laid out here: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
pub fn hash_string_with_salt(s: String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(s.as_bytes(), &salt)?.to_string();
    Ok(hash)
}

/// A function which checks whether the first string can be hashed into the second string.
/// Returns a boolean true if they are the same, and false otherwise.
pub fn compare_hashed_strings(orignal: String, hashed: String) -> Result<bool, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&hashed)?;
    Ok(argon2.verify_password(orignal.as_bytes(), &parsed_hash).is_ok())
}
