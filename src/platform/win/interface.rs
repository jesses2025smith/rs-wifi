use std::{collections::HashSet, rc::Rc};
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL}, NetworkManagement::WiFi::*},
};
use getset::Getters;

use crate::{{AkmType, AuthAlg, IFaceStatus}, error::Error, platform::WiFiInterface, profile::Profile, Result, CipherType};
use super::{util, Handle};

#[derive(Debug, Clone, Getters)]
pub struct Interface {
    #[getset(get = "pub")]
    pub(crate) name: String,
    pub(crate) handle: Rc<Handle>,
    pub(crate) guid: GUID,
}

impl Interface {
    #[inline]
    fn handle(&self) -> HANDLE {
        self.handle.0.to_owned()
    }
}

impl WiFiInterface for Interface {
    fn scan(&self) -> Result<()> {
        let ret = unsafe { WlanScan(self.handle(), &self.guid, None, None, None) };
        util::fix_error(ret)
    }

    fn scan_results(&self) -> Result<HashSet<Profile>> {
        let mut p_networks: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
        let ret = unsafe {
            WlanGetAvailableNetworkList(self.handle(), &self.guid, 2, None, &mut p_networks)
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
                rsutil::trace!("{:?}", ssid);
                rsutil::trace!("strProfileName: {:?}", util::width_slice_to_str(&info.strProfileName));
                rsutil::trace!("dot11BssType: {}", info.dot11BssType.0);
                rsutil::trace!("uNumberOfBssids: {}", info.uNumberOfBssids);
                rsutil::trace!("bNetworkConnectable: {}", info.bNetworkConnectable.as_bool());
                rsutil::trace!("wlanNotConnectableReason: {}", info.wlanNotConnectableReason);
                rsutil::trace!("uNumberOfPhyTypes: {}", info.uNumberOfPhyTypes);
                rsutil::trace!("dot11PhyTypes: {:?}", info.dot11PhyTypes);
                rsutil::trace!("bMorePhyTypes: {}", info.bMorePhyTypes.as_bool());
                rsutil::trace!("wlanSignalQuality: {}", info.wlanSignalQuality);
                rsutil::trace!("bSecurityEnabled: {}", info.bSecurityEnabled.as_bool());
                rsutil::trace!("dot11DefaultAuthAlgorithm: {}", info.dot11DefaultAuthAlgorithm.0);
                rsutil::trace!("dot11DefaultCipherAlgorithm: {}", info.dot11DefaultCipherAlgorithm.0);
                rsutil::trace!("dwFlags: {}", info.dwFlags);
                rsutil::trace!();
                match ssid.uSSIDLength {
                    0 => None,
                    len => {
                        let ssid = String::from_utf8_lossy(&ssid.ucSSID[..len as _]);
                        let mut profile = Profile::new(ssid);

                        if info.bSecurityEnabled.as_bool() {
                            profile.auth = AuthAlg::Shared
                        }

                        let auth = info.dot11DefaultAuthAlgorithm;
                        if matches!(auth, DOT11_AUTH_ALGO_RSNA | DOT11_AUTH_ALGO_RSNA_PSK) {
                            profile.add_akm(AkmType::Wpa)
                        }
                        else if matches!(auth, DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_NONE) {
                            profile.add_akm(AkmType::WpaPsk)
                        }
                        else if matches!(auth, DOT11_AUTH_ALGO_WPA3 | DOT11_AUTH_ALGO_WPA3_ENT | DOT11_AUTH_ALGO_WPA3_ENT_192 | DOT11_AUTH_ALGO_WPA3_SAE) {
                            profile.add_akm(AkmType::Wpa2)
                        }
                        else if matches!(auth, DOT11_AUTH_ALGO_WPA_PSK) {
                            profile.add_akm(AkmType::Wpa2Psk)
                        }

                        let cipher = info.dot11DefaultCipherAlgorithm;
                        if matches!(cipher, DOT11_CIPHER_ALGO_CCMP | DOT11_CIPHER_ALGO_CCMP_256 | DOT11_CIPHER_ALGO_GCMP | DOT11_CIPHER_ALGO_GCMP_256) {
                            profile.cipher = CipherType::Ccmp
                        }
                        else if matches!(cipher, DOT11_CIPHER_ALGO_TKIP) {
                            profile.cipher = CipherType::Tkip
                        }
                        else if matches!(cipher, DOT11_CIPHER_ALGO_WEP | DOT11_CIPHER_ALGO_WEP104 | DOT11_CIPHER_ALGO_WEP40) {
                            profile.cipher = CipherType::Wep
                        }

                        Some(profile)
                    }
                }
            })
            .collect::<HashSet<_>>();
        unsafe { WlanFreeMemory(p_networks as _) };

        Ok(networks)
    }

    fn connect(&self, ssid: &str) -> Result<bool> {
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
            WlanConnect(self.handle(), &self.guid, &params, None)
        };

        Ok(util::fix_error(ret).is_ok())
    }

    fn disconnect(&self) -> Result<()> {
        let ret = unsafe {
            WlanDisconnect(self.handle(), &self.guid, None)
        };
        util::fix_error(ret)
    }

    fn add_network_profile(&self, profile: &Profile) -> Result<()> {
        let xml = profile.to_xml()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        let mut reason_code = 0;
        let ret = unsafe {
            WlanSetProfile(
                self.handle(),
                &self.guid,
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
                    rsutil::warn!("{}", util::width_slice_to_str(&buffer));
                }
                e
            })?;

        Ok(())
    }

    fn network_profile_name_list(&self) -> Result<Vec<String>> {
        let mut p_profiles: *mut WLAN_PROFILE_INFO_LIST = std::ptr::null_mut();
        let ret = unsafe {
            WlanGetProfileList(self.handle(), &self.guid, None, &mut p_profiles)
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

    fn network_profiles(&self) -> Result<Vec<Profile>> {
        let profiles = self.network_profile_name_list()?;

        let mut results = vec![];
        for p in profiles {
            let name = p.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let mut p_xml = PWSTR::default();
            let ret = unsafe {
                WlanGetProfile(
                    self.handle(),
                    &self.guid,
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

            let mut profile = Profile::new(ssid);
            if util::AUTH_LIST.contains(auth) {
                if util::AUTH_LIST2.contains(auth) {
                    profile.auth = AuthAlg::try_from(auth)?;
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

    fn remove_network_profile(&self, name: &str) -> Result<()> {
        let name_wide = name.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let ret = unsafe {
            WlanDeleteProfile(self.handle(), &self.guid, PCWSTR(name_wide.as_ptr()), None)
        };

        util::fix_error(ret)
    }

    fn remove_all_network_profiles(&self) -> Result<()> {
        let profiles = self.network_profile_name_list()?;
        for p in profiles {
            self.remove_network_profile( &p)?;
        }

        Ok(())
    }

    fn status(&self) -> Result<IFaceStatus> {
        let mut size = 0;
        let mut p_data = std::ptr::null_mut();
        let mut opcode_val_type = WLAN_OPCODE_VALUE_TYPE::default();

        let ret = unsafe {
            WlanQueryInterface(
                self.handle(),
                &self.guid,
                wlan_intf_opcode_interface_state,
                None,
                &mut size,
                &mut p_data,
                Some(&mut opcode_val_type)
            )
        };
        util::fix_error(ret)?;
        if p_data.is_null() {
            return Ok(IFaceStatus::Unknown);
        }

        assert_eq!(size, 4);
        let code = unsafe { *(p_data as *const u32) };
        unsafe { LocalFree(Some(HLOCAL(p_data as _))) };

        Ok(code.into())
    }
}
