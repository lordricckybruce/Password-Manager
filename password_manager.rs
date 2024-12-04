fn main(){
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Oronix Cipher Galois Counter Mode, key is the encyryption key
use aes_gcm::aead::{Aead, NewAead};  // where aes_gem implements encryption, Aead and New Aead provide method of encryption 
use rand::{distributions::Alphanumeric, Rng};   //rand to generate randome values including passwords and encryption
use serde::{Deserialize, Serialize}; // allow rust struct to be converted to/from json for stroage and retrieval
use std::collections::HashMap; // provide tools for working with files
use std::fs::{self, File};
use std::io::{self, Write};

const FILE_PATH: &str = "passwords.json";   //file path where passwords will be stored 
const KEY_FILE: &str = "key.bin";   // path to the file where encryption key will be stored securely

#[derive(Serialize, Deserialize)]
struct PasswordManager {  //struct defines a custom data PasswordManager
    passwords: HashMap<String, String>, //Hashmap allows for efficient storage and retrieval of account-password and pairs, strings reps account namesalso string reps encrypted passwords 
}

impl PasswordManager {
    fn new() -> Self {
        PasswordManager {
            passwords: HashMap::new(),  //new to create an empty PasswordManager with no stored passwords
        }
    }

    fn load() -> Self {   //loads reads password.json file and converts the content in PasswordManager content, if file is missing it creates a new one
        if let Ok(data) = fs::read_to_string(FILE_PATH) {
            serde_json::from_str(&data).unwrap_or_else(|_| PasswordManager::new())
        } else {
            PasswordManager::new()
        }
    }

    fn save(&self) {  //save converts PasswordManager to JSON format
        let data = serde_json::to_string_pretty(&self).unwrap();   ///writes to a passwords.json file
        fs::write(FILE_PATH, data).expect("Unable to save passwords.");
    }
}

// Generates a new encryption key and saves it
fn generate_or_load_key() -> Key<Aes256Gcm> {  //checks if encryption key exists in ky.bin
    if let Ok(key_data) = fs::read(KEY_FILE) { //if yes, it reads and loads the key
        Key::from_slice(&key_data)
    } else {
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        fs::write(KEY_FILE, &key).expect("Unable to save key.");
        Key::from_slice(&key)   // otherwise generates froma random 32-byte key, saves it and returns it
    }
}

fn encrypt_password(key: &Key<Aes256Gcm>, plaintext: &str) -> String {  //encrypts plaintext
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b"unique nonce"); // In practice, use a random nonce
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())   //converts the results to Base64 STorage
        .expect("Encryption failed.");
    base64::encode(&ciphertext)
}

fn decrypt_password(key: &Key<Aes256Gcm>, ciphertext: &str) -> String {  //decrypt base 64 code
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b"unique nonce"); // Use the same nonce
    let plaintext = cipher
        .decrypt(nonce, base64::decode(ciphertext).unwrap().as_ref())
        .expect("Decryption failed.");
    String::from_utf8(plaintext).unwrap() //converts back to plaintext
}

fn generate_password(length: usize) -> String {  // generates a random password of the specified length using letters and digits
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
//this stage intializes encryption key
fn main() {
    let key = generate_or_load_key();
    let mut manager = PasswordManager::load();

    loop {
        println!("\n=== Rust Password Manager ===");
        println!("1. Generate Password");
        println!("2. Add Password");
        println!("3. Retrieve Password");
        println!("4. Exit");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {    //gENERATE PASSWORD
            "1" => {
                println!("Enter password length:");
                let mut length = String::new();
                io::stdin().read_line(&mut length).unwrap();
                let length: usize = length.trim().parse().unwrap_or(12);
                println!("Generated Password: {}", generate_password(length));
            }
            "2" => {  //ADD PASSWORD
                println!("Enter account name:");
                let mut account = String::new();
                io::stdin().read_line(&mut account).unwrap();
                let account = account.trim();

                println!("Enter password (or press Enter to generate):");
                let mut password = String::new();
                io::stdin().read_line(&mut password).unwrap();
                let password = if password.trim().is_empty() {
                    let generated = generate_password(12);
                    println!("Generated Password: {}", generated);
                    generated
                } else {
                    password.trim().to_string()
                };

                let encrypted = encrypt_password(&key, &password);
                manager.passwords.insert(account.to_string(), encrypted);
                manager.save();
                println!("Password saved successfully!");
            }
            "3" => {   // ADD PASSWORD
                println!("Enter account name:");
                let mut account = String::new();
                io::stdin().read_line(&mut account).unwrap();
                let account = account.trim();

                if let Some(encrypted) = manager.passwords.get(account) {
                    let password = decrypt_password(&key, encrypted);
                    println!("Password for {}: {}", account, password);
                } else {
                    println!("No password found for this account.");
                }
            }
            "4" => {    //EXIT
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid choice! Please try again."),
        }
    }
}

