
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", _0)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Other(format!("IO error: {}", e).into())
    }
}

#[cfg(target_os = "windows")]
impl From<windows::core::Error> for Error {
    #[inline]
    fn from(e: windows::core::Error) -> Self {
        Self::Other(format!("Windows error: {}", e).into())
    }
}
