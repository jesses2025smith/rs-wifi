use crate::*;
use lazy_static::lazy_static;
use std::collections::HashSet;
use windows::{
    Win32::Foundation::ERROR_SUCCESS,
    Win32::NetworkManagement::WiFi::{WLAN_API_VERSION_1_0, WLAN_API_VERSION_2_0},
    Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW},
    core::{Error as WinError, HRESULT},
};

lazy_static! {
    pub(crate) static ref RE_SSID: regex::Regex = regex::Regex::new(r"<name>(.*)</name>").unwrap();
    pub(crate) static ref RE_AUTH: regex::Regex =
        regex::Regex::new(r"<authentication>(.*)</authentication>").unwrap();
    pub(crate) static ref AUTH_LIST: HashSet<String> = [
        AkmType::None.to_string(),
        AkmType::Wpa.to_string(),
        AkmType::WpaPsk.to_string(),
        AkmType::Wpa2.to_string(),
        AkmType::Wpa2Psk.to_string(),
        AkmType::Other.to_string(),
    ]
    .into_iter()
    .collect();
    pub(crate) static ref AUTH_LIST2: HashSet<String> =
        [AuthAlg::Open.to_string(), AuthAlg::Shared.to_string(),]
            .into_iter()
            .collect();
};

pub(crate) fn wlan_api_ver() -> Result<u32> {
    unsafe {
        let mut osvi = OSVERSIONINFOW::default();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as _;
        GetVersionExW(&mut osvi).map_err(Into::<Error>::into)?;

        let major_ver = osvi.dwMajorVersion;
        let minor_ver = osvi.dwMinorVersion;
        if major_ver > 6 || (major_ver == 6 && minor_ver > 1) {
            Ok(WLAN_API_VERSION_2_0)
        } else {
            Ok(WLAN_API_VERSION_1_0) // winxp
        }
    }
}

#[inline]
pub(crate) fn width_slice_to_str(src: &[u16]) -> String {
    let position = src.iter().position(|&x| x == 0).unwrap_or(src.len());
    String::from_utf16_lossy(&src[..position])
}

pub(crate) fn fix_error(code: u32) -> Result<()> {
    if code != ERROR_SUCCESS.0 {
        Err(Into::<Error>::into(WinError::from(HRESULT(code as i32))))
    } else {
        Ok(())
    }
}

impl From<u32> for IFaceStatus {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Inactive,
            1 => Self::Connected,
            2 => Self::Connected,
            3 => Self::Disconnected,
            4 => Self::Disconnected,
            5 => Self::Connecting,
            6 => Self::Connecting,
            7 => Self::Connecting,
            _ => Self::Unknown,
        }
    }
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
