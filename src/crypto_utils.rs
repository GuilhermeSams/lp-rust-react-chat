use aes::Aes128;
use base64::{decode, encode};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::Rng;
use std::error::Error;
use std::fmt;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

const KEY: &[u8] = b"verysecretkey123"; // chave de 128 bits (16 bytes)
const IV_SIZE: usize = 16; // tamanho do IV de 128 bits (16 bytes)

#[derive(Debug)]
struct CryptoError {
    details: String,
}

impl CryptoError {
    fn new(msg: &str) -> CryptoError {
        CryptoError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for CryptoError {}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::new(&err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for CryptoError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        CryptoError::new(&err.to_string())
    }
}

pub fn encrypt_message(message: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill(&mut iv);

    let mut cipher = Aes128Ctr::new(KEY.into(), &iv.into());
    let mut ciphertext = message.as_bytes().to_vec();
    cipher.apply_keystream(&mut ciphertext);

    let mut result = iv.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(encode(&result)) // codifica em base64
}

pub fn decrypt_message(encoded_message: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let decoded_message = decode(encoded_message)?; // decodifica de base64
    let (iv, ciphertext) = decoded_message.split_at(IV_SIZE);

    let mut cipher = Aes128Ctr::new(KEY.into(), iv.into());
    let mut decrypted = ciphertext.to_vec();
    cipher.apply_keystream(&mut decrypted);

    let result = String::from_utf8(decrypted)?;
    Ok(result)
}