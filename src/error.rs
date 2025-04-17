
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0:?}")]
    IoError(std::io::Error),
    #[error("Os error: {0}")]
    OsError(String),
    #[error("{}", _0)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[cfg(target_os = "linux")]
impl From<nix::errno::Errno> for Error {
    #[inline]
    fn from(e: nix::errno::Errno) -> Self {
        Self::OsError(format!("{}", e))
    }
}

#[cfg(target_os = "linux")]
impl From<std::ffi::OsString> for Error {
    #[inline]
    fn from(s: std::ffi::OsString) -> Self {
        Self::OsError(format!("{:?}", s))
    }
}


#[cfg(target_os = "windows")]
impl From<windows::core::Error> for Error {
    #[inline]
    fn from(e: windows::core::Error) -> Self {
        Self::OsError(format!("{}", e))
    }
}
