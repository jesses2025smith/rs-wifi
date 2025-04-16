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

impl TryFrom<&str> for AuthAlg {
    type Error = Error;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        match v.to_lowercase().as_str() {
            "open" => Ok(AuthAlg::Open),
            "shared" => Ok(AuthAlg::Shared),
            _ => Err(Error::Other(format!("Invalid auth alg: {}", v).into())),
        }
    }
}

impl std::fmt::Display for AuthAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Shared => write!(f, "shared"),
        }
    }
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

impl From<&str> for AkmType {

    fn from(v: &str) -> Self {
        match v.to_lowercase().as_str() {
            "none" => AkmType::None,
            "wpa" => AkmType::Wpa,
            "wpapsk" => AkmType::WpaPsk,
            "wpa2" => AkmType::Wpa2,
            "wpa2psk" => AkmType::Wpa2Psk,
            _ => AkmType::Other,
        }
    }
}

impl std::fmt::Display for AkmType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AkmType::None => write!(f, "NONE"),
            AkmType::Wpa => write!(f, "WPA"),
            AkmType::WpaPsk => write!(f, "WPAPSK"),
            AkmType::Wpa2 => write!(f, "WPA2"),
            AkmType::Wpa2Psk => write!(f, "WPA2PSK"),
            AkmType::Other => write!(f, "OTHER"),
        }
    }
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

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Wep => write!(f, "WEP"),
            Self::Tkip => write!(f, "TKIP"),
            Self::Ccmp => write!(f, "AES"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}
