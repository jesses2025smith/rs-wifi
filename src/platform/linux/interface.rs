use std::{collections::HashSet, rc::Rc, os::fd::AsRawFd as _, path::PathBuf};
use getset::Getters;
use nix::sys::socket;

use crate::{error::Error, AkmType, CipherType, IFaceStatus, platform::WiFiInterface, profile::Profile, Result};
use super::{util, Handle, socket_file};

const CTRL_IFACE_RETRY: usize = 3;
const REPLY_SIZE: usize = 4096;

#[derive(Debug, Clone, Getters)]
pub struct Interface {
    #[getset(get = "pub")]
    pub(crate) name: String,
    pub(crate) handle: Rc<Handle>,
}

unsafe impl Sync for Interface {}
unsafe impl Send for Interface {}

impl Interface {
    pub(crate) fn new(ctrl_iface: PathBuf) -> Result<Option<Self>> {
        let iface = ctrl_iface.file_name()
            .ok_or(Error::Other(format!("{:?} is no filename", ctrl_iface).into()))?
            .to_os_string()
            .into_string()
            .map_err(Into::<Error>::into)?;
        let sock_file = socket_file(&iface);
        util::remove_file(&sock_file)?;

        let sock = socket::socket(
            socket::AddressFamily::Unix,
            socket::SockType::Datagram,
            socket::SockFlag::empty(), None
        )
            .map_err(Into::<Error>::into)?
            .as_raw_fd();
        let addr = socket::UnixAddr::new(sock_file.as_str())
            .map_err(Into::<Error>::into)?;
        socket::bind(sock, &addr)
            .map_err(Into::<Error>::into)?;
        let addr = socket::UnixAddr::new(ctrl_iface.as_path())
            .map_err(Into::<Error>::into)?;
        socket::connect(sock, &addr)
            .map_err(Into::<Error>::into)?;

        let len = socket::send(sock, "PING".as_bytes(), socket::MsgFlags::empty())
            .map_err(Into::<Error>::into)?;
        rsutil::debug!("Sent `PING` returned: {}", len);
        for _ in 0..CTRL_IFACE_RETRY {
            let mut buffer = [0u8; REPLY_SIZE];
            let reply = socket::recv(sock, &mut buffer, socket::MsgFlags::empty())
                .map_err(Into::<Error>::into)?;
            if reply == 0 {
                rsutil::error!("Connection to {} is broken!", iface);
                break
            }

            if String::from_utf8_lossy(&buffer[..reply]).starts_with("PONG") {
                rsutil::info!("Connection to socket {} successfully!", iface);
                return Ok(Some(Self {
                    name: iface.clone(),
                    handle: Rc::new(Handle {
                        iface,
                        fd: sock,
                    }),
                }));
            }
        }

        Ok(None)
    }

    fn _send_cmd_to_wpas(&self, cmd: &str, get_repy: bool) -> Result<Option<String>> {
        let len = socket::send(self.handle.fd, cmd.as_bytes(), socket::MsgFlags::empty())
            .map_err(Into::<Error>::into)?;
        if !cmd.contains("psk") {
            rsutil::debug!("Sending command: {} to wpa_s: {}", cmd, len);
        }
        if len == 0 {
            return Err(Error::Other(format!("Failed to send command: {}", cmd).into()));
        }

        let mut buffer = [0u8; REPLY_SIZE];
        let reply = socket::recv(self.handle.fd, &mut buffer, socket::MsgFlags::empty())
            .map_err(Into::<Error>::into)?;
        let result = String::from_utf8_lossy(&buffer[..reply]);
        if get_repy {
            return Ok(Some(result.to_string()));
        }

        if !result.eq_ignore_ascii_case("Ok\n") {
            rsutil::error!("Unexpected resp '{}' for Command '{}'", result, cmd);
        }

        Ok(None)
    }
}

impl WiFiInterface for Interface {
    fn scan(&self) -> Result<()> {
        let _ = self._send_cmd_to_wpas("SCAN", false)?;
        Ok(())
    }

    fn scan_results(&self) -> Result<HashSet<Profile>> {
        let reply = self._send_cmd_to_wpas("SCAN_RESULTS", true)?
            .unwrap();

        Ok(reply.lines()
            .skip(1)
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let bssid = parts.next()?;
                let _ = parts.next()?;  // frequency
                let _ = parts.next()?;  // rssi
                let akm = parts.next()?;
                let ssid = parts.next()?;
                let mut profile = Profile::new(ssid)
                    .with_bssid(Some(bssid.into()));
                if akm.contains("WPA-PSK") {
                    profile.add_akm(AkmType::WpaPsk);
                }
                if akm.contains("WPA2-PSK") {
                    profile.add_akm(AkmType::Wpa2Psk);
                }
                if akm.contains("WPA-EAP") {
                    profile.add_akm(AkmType::Wpa);
                }
                if akm.contains("WPA2-EAP") {
                    profile.add_akm(AkmType::Wpa2);
                }

                Some(profile)
            })
            .collect::<HashSet<_>>())
    }

    fn connect(&self, ssid: &str) -> Result<bool> {
        rsutil::debug!("Connecting to network: {}", ssid);
        let mut flag = false;
        for (i, s) in self.network_profile_name_list()?
            .iter()
            .enumerate() {
            if ssid == s {
                let reply = self._send_cmd_to_wpas(&format!("SELECT_NETWORK {}", i), true)?.unwrap();
                if reply.to_lowercase() != "OK" {
                    rsutil::error!("Failed({}) to connect to network: {}", reply, ssid);
                }
                else {
                    rsutil::info!("Connected to network: {}", ssid);
                    flag = true;
                }
                break;
            }
        }

        Ok(flag)
    }

    fn disconnect(&self) -> Result<()> {
        self._send_cmd_to_wpas("DISCONNECT", false)?;
        Ok(())
    }

    fn add_network_profile(&self, profile: &Profile) -> Result<()> {
        let reply = self._send_cmd_to_wpas("ADD_NETWORK", true)?.unwrap();
        let id = reply.trim();

        let _ = self._send_cmd_to_wpas(&format!("SET_NETWORK {} ssid \"{}\"", id, profile.ssid()), false)?;
        let akm: &AkmType = profile.akm()
            .last()
            .unwrap_or(&AkmType::None);
        let key_mgmt = akm.key_mgmt();
        if !key_mgmt.is_empty() {
            let _ = self._send_cmd_to_wpas(&format!("SET_NETWORK {} key_mgmt {}", id, key_mgmt), false)?;
        }
        let proto = akm.proto();
        if !proto.is_empty() {
            let _ = self._send_cmd_to_wpas(&format!("SET_NETWORK {} proto {}", id, proto), false)?;
        }
        if akm.key_required() {
            let key = match profile.key() {
                Some(v) => v,
                None => &String::default(),
            };
            let _ = self._send_cmd_to_wpas(&format!("SET_NETWORK {} psk \"{}\"", id, key), false)?;
        }

        Ok(())
    }

    fn network_profile_name_list(&self) -> Result<Vec<String>> {
        let reply = self._send_cmd_to_wpas("LIST_NETWORKS", true)?.unwrap();
        Ok(reply.lines()
            .skip(1)
            .filter_map(|line| {
                let ssid = line.split_whitespace()
                    .skip(1)
                    .nth(1)?;
                Some(ssid.into())
            })
            .collect())
    }

    fn network_profiles(&self) -> Result<Vec<Profile>> {
        let len = self.network_profile_name_list()?.len();

        let mut results = vec![];
        for i in 0..len {
            let ssid = self._send_cmd_to_wpas(&format!("GET_NETWORK {} ssid", i), true)?.unwrap();
            let key_mgmt = self._send_cmd_to_wpas(&format!("GET_NETWORK {} key_mgmt", i), true)?.unwrap();
            let key_mgmt = key_mgmt.to_uppercase();
            if key_mgmt.contains("FAIL") {
                continue;
            }
            let ciphers = self._send_cmd_to_wpas(&format!("GET_NETWORK {} pairwise", i), true)?.unwrap();
            let ciphers = ciphers.to_uppercase();
            if ciphers.contains("FAIL") {
                continue;
            }
            let mut profile = Profile::new(ssid.trim());
            profile.id = i;
            if key_mgmt.contains("WPA-PSK") {
                let rep =   self._send_cmd_to_wpas(&format!("GET_NETWORK {} proto", i), true)?.unwrap();
                if rep.to_uppercase() == "RSN" {
                    profile.add_akm(AkmType::Wpa2Psk);
                }
                else {
                    profile.add_akm(AkmType::WpaPsk);
                }
            }
            else if key_mgmt.contains("WPA-EAP") {
                let rep =   self._send_cmd_to_wpas(&format!("GET_NETWORK {} proto", i), true)?.unwrap();
                if rep.to_uppercase() == "RSN" {
                    profile.add_akm(AkmType::Wpa2);
                }
                else {
                    profile.add_akm(AkmType::Wpa);
                }
            }

            let ciphers = ciphers.split_whitespace();
            let mut first = None;
            for c in ciphers {
                if c.contains("CCMP") {
                    profile.cipher = CipherType::Ccmp;
                    first = None;
                    break;
                }
                first = Some(c);
            }
            if let Some(v) = first {
                profile.cipher = match v {
                    "CCMP" => CipherType::Ccmp,
                    "TKIP" => CipherType::Tkip,
                    "WEP" => CipherType::Wep,
                    _ => CipherType::Unknown,
                }
            }

            results.push(profile);
        }

        Ok(results)
    }

    fn remove_network_profile(&self, name: &str) -> Result<()> {
        let profiles = self.network_profiles()?;
        for p in profiles {
            if p.ssid == name {
                let _ = self._send_cmd_to_wpas(&format!("REMOVE_NETWORK {}", p.id), false)?;
                break;
            }
        }

        Ok(())
    }

    fn remove_all_network_profiles(&self) -> Result<()> {
        let _ = self._send_cmd_to_wpas("REMOVE_NETWORK all", false)?;
        Ok(())
    }

    fn status(&self) -> Result<IFaceStatus> {
        let reply = self._send_cmd_to_wpas("STATUS", true)?.unwrap();
        let mut status = IFaceStatus::Unknown;
        for line in reply.lines() {
            if line.starts_with("wpa_state=") {
                status = line.split('=').nth(1)
                    .ok_or(Error::Other("Failed to parse wpa_state".into()))?
                    .to_lowercase()
                    .into();
                break;
            }
        }

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::WiFiInterface;
    use super::Interface;

    #[test]
    fn test_new() -> anyhow::Result<()> {
        let iface = Interface::new(PathBuf::from("/var/run/wpa_supplicant/wlp11s0"))?
            .unwrap();
        let result = iface.scan_results()?;
        println!("result: {:?}", result);
        iface.connect("TestSSID")?;

        Ok(())
    }
}


