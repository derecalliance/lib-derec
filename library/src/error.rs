use std::fmt;

#[derive(Debug)]
pub enum Error {
    Crypto(String),
    Decode(String),
    Encode(String),
    InvalidInput(String),
    MissingField(&'static str),
    Recovery(String),
    Serialization(String),
    Vss(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto(message) => write!(f, "Crypto error: {message}"),
            Error::Decode(message) => write!(f, "Decode error: {message}"),
            Error::Encode(message) => write!(f, "Encode error: {message}"),
            Error::InvalidInput(message) => write!(f, "Invalid input: {message}"),
            Error::MissingField(field) => write!(f, "Missing field: {field}"),
            Error::Recovery(message) => write!(f, "Recovery error: {message}"),
            Error::Serialization(message) => write!(f, "Serialization error: {message}"),
            Error::Vss(message) => write!(f, "VSS error: {message}"),
        }
    }
}

impl std::error::Error for Error {}
