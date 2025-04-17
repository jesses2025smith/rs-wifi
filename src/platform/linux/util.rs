use nix::sys::stat;
use crate::*;

pub(crate) const S_IFSOCK: stat::SFlag = stat::SFlag::S_IFSOCK;

pub(crate) fn remove_file(name: &str) -> Result<()> {
    if std::fs::exists(name)
        .map_err(Into::<Error>::into)? {
        let mode = stat::stat(name)
            .map_err(Into::<Error>::into)?
            .st_mode;
        if stat::SFlag::from_bits_truncate(mode).contains(S_IFSOCK) {
            std::fs::remove_file(name)
                .map_err(Into::<Error>::into)?;
        }
    }

    Ok(())
}

impl From<&str> for IFaceStatus {
    fn from(v: &str) -> Self {
        match v {
            "completed" => Self::Connected,
            "inactive" => Self::Inactive,
            "authenticating" => Self::Connecting,
            "associating" => Self::Connecting,
            "associated" => Self::Connecting,
            "4way_handshake" => Self::Connecting,
            "group_handshake" => Self::Connecting,
            "interface_disabled" => Self::Inactive,
            "disconnected" => Self::Disconnected,
            "scanning" => Self::Scanning,
            _ => Self::Unknown,
        }
    }
}

impl From<String> for IFaceStatus {
    #[inline]
    fn from(v: String) -> Self {
        v.as_str().into()
    }
}

impl AkmType {
    pub fn key_mgmt(&self) -> &str {
        match self {
            Self::Wpa => "WPA-EAP",
            Self::WpaPsk => "WPA-PSK",
            Self::Wpa2 => "WPA-EAP",
            Self::Wpa2Psk => "WPA-PSK",
            Self::None => "NONE",
            _ => "",
        }
    }

    pub fn proto(&self) -> &str {
        match self {
            Self::Wpa => "WPA",
            Self::WpaPsk => "WPA",
            Self::Wpa2 => "RSN",
            Self::Wpa2Psk => "RSN",
            _ => "",
        }
    }

    #[inline]
    pub fn key_required(&self) -> bool {
        matches!(self, Self::WpaPsk | Self::Wpa2Psk)
    }
}

