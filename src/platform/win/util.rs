use lazy_static::lazy_static;
use std::collections::HashSet;
use windows::{
    core::{HRESULT, Error as WinError},
    Win32::Foundation::ERROR_SUCCESS,
    Win32::NetworkManagement::WiFi::{WLAN_API_VERSION_1_0, WLAN_API_VERSION_2_0},
    Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW},
};
use crate::{{AkmType, AuthAlg}, error::Error, Result};

lazy_static!(
    pub(crate) static ref RE_SSID: regex::Regex = regex::Regex::new(r"<name>(.*)</name>").unwrap();
    pub(crate) static ref RE_AUTH: regex::Regex = regex::Regex::new(r"<authentication>(.*)</authentication>").unwrap();
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
pub(crate) static ref AUTH_LIST2: HashSet<String> = [
        AuthAlg::Open.to_string(),
        AuthAlg::Shared.to_string(),
    ]
    .into_iter()
    .collect();
);

pub(crate) fn wlan_api_ver() -> Result<u32> {
    unsafe {
        let mut osvi = OSVERSIONINFOW::default();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as _;
        GetVersionExW(&mut osvi)
            .map_err(Into::<Error>::into)?;

        if osvi.dwMajorVersion > 5 && osvi.dwMinorVersion > 1 {
            Ok(WLAN_API_VERSION_1_0)
        }
        else {
            Ok(WLAN_API_VERSION_2_0)
        }
    }
}

#[inline]
pub(crate) fn width_slice_to_str(src: &[u16]) -> String {
    let position = src.iter().position(|&x| x == 0).unwrap_or(src.len());
    String::from_utf16_lossy(
        &src[..position]
    )
}

pub(crate) fn fix_error(code: u32) -> Result<()> {
    if code != ERROR_SUCCESS.0 {
        Err(Into::<Error>::into(WinError::from(HRESULT(code as i32))))
    }
    else {
        Ok(())
    }
}
