use thiserror::Error;

#[derive(Debug, Error)]
pub enum KrcmError {
    #[error("invalid container format")]
    Format,
    #[error("authentication failed")]
    Authentication,
    #[error("invalid password")]
    InvalidPassword,
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("io error")]
    Io,
    #[error("internal error")]
    Internal,
}

impl From<std::io::Error> for KrcmError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
