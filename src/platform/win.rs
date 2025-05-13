mod interface;
mod util;

pub use interface::Interface;

use std::rc::Rc;
use windows::Win32::{Foundation::HANDLE, NetworkManagement::WiFi::*};
use crate::Result;

#[derive(Debug, Clone)]
pub(crate) struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        let ret = unsafe {
            WlanCloseHandle(self.0, None)
        };

        if let Err(e) = util::fix_error(ret) {
            rsutil::warn!("Failed to close handle: {}", e);
        }
    }
}

#[derive(Debug)]
pub struct WifiUtil {
    // nego_ver: u32,
    handle: Rc<Handle>,
}

impl WifiUtil {
    pub fn new() -> Result<Self> {
        let mut nego_ver = 0;
        let mut handle = HANDLE::default();

        let ret = unsafe { WlanOpenHandle(util::wlan_api_ver()?, None, &mut nego_ver, &mut handle) };
        util::fix_error(ret)?;
        let handle = Rc::new(Handle(handle));

        Ok(Self {
            // nego_ver,
            handle,
        })
    }

    pub fn interfaces(&self) -> Result<Vec<Interface>> {
        let mut p_ifaces: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let ret = unsafe { WlanEnumInterfaces(self.handle.0.to_owned(), None, &mut p_ifaces) };
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
            .iter()
            .map(|v| {
                let name = util::width_slice_to_str(&v.strInterfaceDescription);
                let guid = v.InterfaceGuid;
                Interface {
                    name,
                    handle: self.handle.clone(),
                    guid,
                }
            })
            .collect::<Vec<_>>();

        unsafe { WlanFreeMemory(p_ifaces as _) };

        Ok(ifaces)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::Error, AkmType, AuthAlg, CipherType, IFaceStatus, Profile, WiFiInterface as _};

    fn initialize() -> anyhow::Result<Interface> {
        let util = WifiUtil::new()?;
        let iface = util.interfaces()?;
        let iface = iface.first()
            .ok_or(Error::Other("No iface found".into()))?;

        Ok(iface.clone())
    }

    #[test]
    fn test_scan() -> anyhow::Result<()> {
        let iface = initialize()?;
        iface.scan()?;
        std::thread::sleep(std::time::Duration::from_secs(5));
        let results = iface.scan_results()?;
        rsutil::trace!("Scan results: {:?}", results);

        Ok(())
    }

    #[test]
    #[ignore = "reason: a real ssid is required"]
    fn test_connect() -> anyhow::Result<()> {
        let iface = initialize()?;

        iface.disconnect()?;
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(iface.status()?, IFaceStatus::Disconnected);

        iface.connect("TestSSID-5G")?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(iface.status()?, IFaceStatus::Connected);

        Ok(())
    }

    #[test]
    fn test_add_profile() -> anyhow::Result<()> {
        let iface = initialize()?;
        let before = iface.network_profile_name_list()?;
        let ssid = "TestSSID";
        let key = "12345678";
        let mut profile = Profile::new(ssid)
            .with_key(Some(key.into()))
            .with_auth(AuthAlg::Open)
            .with_cipher(CipherType::Ccmp);
        profile.add_akm(AkmType::Wpa2Psk);
        iface.add_network_profile(&profile)?;
        let after = iface.network_profile_name_list()?;
        assert_eq!(before.len() + 1, after.len());
        iface.remove_network_profile(&ssid)?;
        let after = iface.network_profile_name_list()?;
        assert_eq!(before.len(), after.len());

        Ok(())
    }

    #[test]
    #[ignore = "reason: tested in [`test_add_profile`]"]
    fn test_profile_list() -> anyhow::Result<()> {
        let iface = initialize()?;

        iface.network_profile_name_list()?
            .iter()
            .enumerate()
            .for_each(|(i, profile)| {
                rsutil::trace!("({})ProfileName: {}", i, profile);
            });

        Ok(())
    }

    #[test]
    fn test_profiles() -> anyhow::Result<()> {
        let iface = initialize()?;
        let results = iface.network_profiles()?;
        rsutil::trace!("Profiles: {:?}", results);

        Ok(())
    }

    #[test]
    #[ignore = "reason: a real ssid is required and tested in [`test_add_profile`]"]
    fn test_remove_profile() -> anyhow::Result<()> {
        let iface = initialize()?;
        let before = iface.network_profile_name_list()?;
        iface.remove_network_profile("TestSSID-5G")?;
        let after = iface.network_profile_name_list()?;
        assert_eq!(before.len() - 1, after.len());

        Ok(())
    }
}
