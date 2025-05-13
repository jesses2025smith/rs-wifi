mod error;
mod platform;
mod profile;

pub use error::*;
pub use platform::*;
pub use profile::*;

pub type Result<T, E = error::Error> = std::result::Result<T, E>;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum IFaceStatus {
    Disconnected,
    Scanning,
    Inactive,
    Connecting,
    Connected,
    Unknown,
}

#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum AuthAlg {
    #[default]
    Open,
    Shared,
}

#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum AkmType {
    #[default]
    None,
    Wpa,
    WpaPsk,
    Wpa2,
    Wpa2Psk,
    Other,
}

#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CipherType {
    #[default]
    None,
    Wep,
    Tkip,
    Ccmp,
    Unknown,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum ConnectMode {
    Manual,
    #[default]
    Auto,
}

#[cfg(target_os = "windows")]
impl std::fmt::Display for ConnectMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectMode::Manual => write!(f, "manual"),
            ConnectMode::Auto => write!(f, "auto"),
        }
    }
}
