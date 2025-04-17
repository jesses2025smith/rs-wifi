pub mod error;
pub mod platform;
pub mod profile;

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
