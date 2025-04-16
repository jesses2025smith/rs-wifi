mod util;

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
                commty::warn!("{}", e);
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

    pub fn scan(&self, guid: &GUID) -> Result<()> {
        let ret = unsafe { WlanScan(self.handle, guid, None, None, None) };
        util::fix_error(ret)
    }

    pub fn scan_results(&self, guid: &GUID) -> Result<HashSet<String>> {
        let mut p_networks: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
        let ret = unsafe {
            WlanGetAvailableNetworkList(self.handle, guid, 2, None, &mut p_networks)
        };

        util::fix_error(ret)
            .map_err(|e| {
                unsafe { WlanFreeMemory(p_networks as _) };
                e
            })?;

        if p_networks.is_null() {
            return Ok(Default::default());
        }

        let deref = unsafe { &*p_networks };
        let networks = unsafe {
            std::slice::from_raw_parts(
                &deref.Network[0],
                deref.dwNumberOfItems as _,
            )
        }
            .iter()
            .filter_map(|info| {
                let ssid = &info.dot11Ssid;
                commty::trace!("{:?}", ssid);
                commty::trace!("strProfileName: {:?}", util::width_slice_to_str(&info.strProfileName));
                commty::trace!("dot11BssType: {}", info.dot11BssType.0);
                commty::trace!("uNumberOfBssids: {}", info.uNumberOfBssids);
                commty::trace!("bNetworkConnectable: {}", info.bNetworkConnectable.as_bool());
                commty::trace!("wlanNotConnectableReason: {}", info.wlanNotConnectableReason);
                commty::trace!("uNumberOfPhyTypes: {}", info.uNumberOfPhyTypes);
                commty::trace!("dot11PhyTypes: {:?}", info.dot11PhyTypes);
                commty::trace!("bMorePhyTypes: {}", info.bMorePhyTypes.as_bool());
                commty::trace!("wlanSignalQuality: {}", info.wlanSignalQuality);
                commty::trace!("bSecurityEnabled: {}", info.bSecurityEnabled.as_bool());
                commty::trace!("dot11DefaultAuthAlgorithm: {}", info.dot11DefaultAuthAlgorithm.0);
                commty::trace!("dot11DefaultCipherAlgorithm: {}", info.dot11DefaultCipherAlgorithm.0);
                commty::trace!("dwFlags: {}", info.dwFlags);
                commty::trace!();
                match ssid.uSSIDLength {
                    0 => None,
                    len => Some(String::from_utf8_lossy(&ssid.ucSSID[..len as _])
                        .to_string())
                }
            })
            .collect::<HashSet<_>>();
        unsafe { WlanFreeMemory(p_networks as _) };

        Ok(networks)
    }

    pub fn connect(&self, guid: &GUID, ssid: &str) -> Result<()> {
        let ssid_wide = ssid.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut ssid = ssid.as_bytes().to_vec();
        let ssid_len = ssid.len();
        ssid.resize(32, Default::default());
        let mut dot11_ssid = DOT11_SSID {
            uSSIDLength: ssid_len as _,
            ucSSID: ssid.try_into().unwrap(),
        };
        let mut bssid = DOT11_BSSID_LIST::default();

        let params = WLAN_CONNECTION_PARAMETERS {
            wlanConnectionMode: wlan_connection_mode_profile,
            strProfile: PCWSTR(ssid_wide.as_ptr()),
            pDot11Ssid: &mut dot11_ssid,
            pDesiredBssidList: &mut bssid,
            dot11BssType: dot11_BSS_type_infrastructure,
            dwFlags: 0,
        };
        let ret = unsafe {
            WlanConnect(self.handle, guid, &params, None)
        };

        util::fix_error(ret)
    }

    pub fn disconnect(&self, guid: &GUID) -> Result<()> {
        let ret = unsafe {
            WlanDisconnect(self.handle, guid, None)
        };
        util::fix_error(ret)
    }

    pub fn add_network_profile(&self, guid: &GUID, profile: &Profile) -> Result<()> {
        let xml = profile.to_xml()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        let mut reason_code = 0;
        let ret = unsafe {
            WlanSetProfile(
                self.handle,
                guid,
                2,
                PCWSTR(xml.as_ptr()),
                None,
                true,
                None,
                &mut reason_code
            )
        };

        util::fix_error(ret)
            .map_err(|e| {
                let buffer = [0u16; 64];
                let ret = unsafe {
                    WlanReasonCodeToString(reason_code, &buffer, None)
                };
                
                if ret == ERROR_SUCCESS.0 {
                    commty::warn!("{}", util::width_slice_to_str(&buffer));
                }
                e
            })?;

        Ok(())
    }

    pub fn network_profile_name_list(&self, guid: &GUID) -> Result<Vec<String>> {
        let mut p_profiles: *mut WLAN_PROFILE_INFO_LIST = std::ptr::null_mut();
        let ret = unsafe {
            WlanGetProfileList(self.handle, guid, None, &mut p_profiles)
        };

        util::fix_error(ret)
            .map_err(|e| {
                unsafe { WlanFreeMemory(p_profiles as _) };
                e
            })?;

        if p_profiles.is_null() {
            return Ok(Default::default());
        }

        let deref = unsafe { &*p_profiles };
        let results = unsafe {
            std::slice::from_raw_parts(
                &deref.ProfileInfo[0],
                deref.dwNumberOfItems as _
            )
        }
            .iter()
            .map(|info| {
                let result = util::width_slice_to_str(&info.strProfileName);
                result
            })
            .collect::<Vec<_>>();

        unsafe { WlanFreeMemory(p_profiles as _) };

        Ok(results)
    }

    pub fn network_profiles(&self, guid: &GUID) -> Result<Vec<Profile>> {
        let profiles = self.network_profile_name_list(guid)?;

        let mut results = vec![];
        for p in profiles {
            let name = p.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let mut p_xml = PWSTR::default();
            let ret = unsafe {
                WlanGetProfile(
                    self.handle,
                    guid,
                    PCWSTR::from_raw(name.as_ptr()),
                    None,
                    &mut p_xml,
                    None,
                    None,
                )
            };
            util::fix_error(ret)?;

            let xml = unsafe { 
                p_xml.to_string()
                    .map_err(|e| Error::Other(e.into()))?
            };
            let ssid = util::RE_SSID.captures(&xml)
                .ok_or(Error::Other("Can't match ssid".into()))?
                .get(1)
                .ok_or(Error::Other("Can't match ssid".into()))?
                .as_str();

            let auth = util::RE_AUTH.captures(&xml)
                .ok_or(Error::Other("Can't match authentication".into()))?
                .get(1)
                .ok_or(Error::Other("Can't match authentication".into()))?
                .as_str();

            let mut profile = Profile::new(&ssid);
            if util::AUTH_LIST.contains(auth) {
                if util::AUTH_LIST2.contains(auth) {
                    profile.auth = AuthAlg::try_from(auth).unwrap();
                    profile.akm.push(AkmType::None);
                }
                else {
                    profile.auth = AuthAlg::Open;
                }
            }
            else {
                profile.auth = AuthAlg::Open;
                profile.akm.push(AkmType::from(auth));
            }

            results.push(profile);
        }

        Ok(results)
    }

    pub fn remove_network_profile(&self, guid: &GUID, name: &str) -> Result<()> {
        let name_wide = name.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let ret = unsafe {
            WlanDeleteProfile(self.handle, guid, PCWSTR(name_wide.as_ptr()), None)
        };

        util::fix_error(ret)
    }

    pub fn remove_all_network_profiles(&self, guid: &GUID) -> Result<()> {
        let profiles = self.network_profile_name_list(guid)?;
        for p in profiles {
            self.remove_network_profile(guid, &p)?;
        }

        Ok(())
    }

    pub fn status(&self, guid: &GUID) -> Result<IFaceStatus> {
        let mut size = 0;
        let mut p_data = std::ptr::null_mut();
        let mut opcode_val_type = WLAN_OPCODE_VALUE_TYPE::default();

        let ret = unsafe {
            WlanQueryInterface(
                self.handle,
                guid,
                wlan_intf_opcode_interface_state,
                None,
                &mut size,
                &mut p_data,
                Some(&mut opcode_val_type)
            )
        };
        util::fix_error(ret)?;
        assert_eq!(size, 4);
        if p_data.is_null() {
            return Ok(IFaceStatus::Unknown);
        }

        let code = unsafe { *(p_data as *const u32) };
        unsafe { LocalFree(Some(HLOCAL(p_data as _))) };

        Ok(match code {
            0 => IFaceStatus::Inactive,
            1 => IFaceStatus::Connected,
            2 => IFaceStatus::Connected,
            3 => IFaceStatus::Disconnected,
            4 => IFaceStatus::Disconnected,
            5 => IFaceStatus::Connecting,
            6 => IFaceStatus::Connecting,
            7 => IFaceStatus::Connecting,
            _ => IFaceStatus::Unknown,
        })
    }

    pub fn interfaces(&self) -> Result<Vec<WLAN_INTERFACE_INFO>> {
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
        commty::trace!("Scan results: {:?}", results);

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
                commty::trace!("({})ProfileName: {}", i, profile);
            });

        Ok(())
    }

    #[test]
    fn test_profiles() -> anyhow::Result<()> {
        let (util, guid) = initialize()?;
        let results = util.network_profiles(&guid)?;
        commty::trace!("Profiles: {:?}", results);

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
