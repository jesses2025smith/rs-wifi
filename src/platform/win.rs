mod interface;
mod util;

pub use interface::Interface;

use std::collections::HashSet;
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL}, NetworkManagement::WiFi::*},
};
use crate::{{AkmType, AuthAlg, IFaceStatus}, error::Error, profile::Profile, Result};


#[derive(Debug)]
pub struct WifiUtil {
    // nego_ver: u32,
    handle: HANDLE,
}

impl Drop for WifiUtil {
    fn drop(&mut self) {
        let ret = unsafe {
            WlanCloseHandle(self.handle, None)
        };

        let _ = util::fix_error(ret)
            .is_err_and(|e| {
                rsutil::warn!("{}", e);
                true
            });
    }
}

impl WifiUtil {
    pub fn new() -> Result<Self> {
        let mut nego_ver = 0;
        let mut handle = HANDLE::default();

        let ret = unsafe { WlanOpenHandle(util::wlan_api_ver()?, None, &mut nego_ver, &mut handle) };
        util::fix_error(ret)?;

        Ok(Self {
            // nego_ver,
            handle,
        })
    }

    pub fn interfaces(&self) -> Result<Vec<Interface>> {
        let mut p_ifaces: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let ret = unsafe { WlanEnumInterfaces(self.handle, None, &mut p_ifaces) };
        util::fix_error(ret)
            .map_err(|e| {
                unsafe { WlanFreeMemory(p_ifaces as _) };
                e
            })?;

        if p_ifaces.is_null() {
            return Ok(Default::default());
        }

        let deref = unsafe { &*p_ifaces };
        let ifaces = unsafe {
            std::slice::from_raw_parts(
                &deref.InterfaceInfo[0],
                deref.dwNumberOfItems as _,
            )
        }
            .to_vec();

        unsafe { WlanFreeMemory(p_ifaces as _) };

        Ok(ifaces)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CipherType, error::Error};

    fn initialize() -> anyhow::Result<(WifiUtil, GUID)> {
        let util = WifiUtil::new()?;
        let iface = util.interfaces()?;
        let iface = iface.first()
            .ok_or(Error::Other("No iface found".into()))?;

        Ok((util, iface.InterfaceGuid))
    }

    #[test]
    fn test_scan() -> anyhow::Result<()> {
        let (util, guid) = initialize()?;
        util.scan(&guid)?;
        std::thread::sleep(std::time::Duration::from_secs(5));
        let results = util.scan_results(&guid)?;
        rsutil::trace!("Scan results: {:?}", results);

        Ok(())
    }

    #[test]
    #[ignore = "reason: a real ssid is required"]
    fn test_connect() -> anyhow::Result<()> {
        let (util, guid) = initialize()?;

        util.disconnect(&guid)?;
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(util.status(&guid)?, IFaceStatus::Disconnected);

        util.connect(&guid, "TestSSID-5G")?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(util.status(&guid)?, IFaceStatus::Connected);

        Ok(())
    }

    #[test]
    fn test_add_profile() -> anyhow::Result<()> {
        let util = WifiUtil::new()?;
        let iface = util.interfaces()?;
        let iface = iface.first()
            .ok_or(Error::Other("No iface found".into()))?;
        let guid = &iface.InterfaceGuid;
        let before = util.network_profile_name_list(guid)?;
        let ssid = "TestSSID";
        let key = "12345678";
        let mut profile = Profile::new(ssid)
            .with_key(Some(key.into()))
            .with_auth(AuthAlg::Open)
            .with_cipher(CipherType::Ccmp);
        profile.add_akm(AkmType::Wpa2Psk);
        util.add_network_profile(guid, &profile)?;
        let after = util.network_profile_name_list(guid)?;
        assert_eq!(before.len() + 1, after.len());
        util.remove_network_profile(&*guid, &ssid)?;
        let after = util.network_profile_name_list(guid)?;
        assert_eq!(before.len(), after.len());

        Ok(())
    }

    #[test]
    #[ignore = "reason: tested in [`test_add_profile`]"]
    fn test_profile_list() -> anyhow::Result<()> {
        let (util, guid) = initialize()?;

        util.network_profile_name_list(&guid)?
            .iter()
            .enumerate()
            .for_each(|(i, profile)| {
                rsutil::trace!("({})ProfileName: {}", i, profile);
            });

        Ok(())
    }

    #[test]
    fn test_profiles() -> anyhow::Result<()> {
        let (util, guid) = initialize()?;
        let results = util.network_profiles(&guid)?;
        rsutil::trace!("Profiles: {:?}", results);

        Ok(())
    }

    #[test]
    #[ignore = "reason: a real ssid is required and tested in [`test_add_profile`]"]
    fn test_remove_profile() -> anyhow::Result<()> {
        let (util, guid) = initialize()?;
        let before = util.network_profile_name_list(&guid)?;
        util.remove_network_profile(&guid, "TestSSID-5G")?;
        let after = util.network_profile_name_list(&guid)?;
        assert_eq!(before.len() - 1, after.len());

        Ok(())
    }
}
