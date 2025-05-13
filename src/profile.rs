use getset::{CopyGetters, Getters, WithSetters};
use crate::{AkmType, AuthAlg, CipherType};


/// Represents a wireless network profile with associated configuration and methods.
///
/// # Methods
///
/// - `new(ssid: &str) -> Self`:
///   Creates a new `Profile` instance with the given SSID. The default AKM type is set to `None`.
///
/// - `add_akm(&mut self, akm_type: AkmType)`:
///   Adds an AKM (Authentication and Key Management) type to the profile.
///
/// - `to_xml(&self) -> String`:
///   Converts the profile into an XML string representation. The XML includes details such as
///   the SSID, authentication type, encryption type, and optional shared key. The method
///   dynamically adjusts the XML content based on the profile's configuration.
///
/// # XML Output
///
/// The `to_xml` method generates an XML string in the following structure:
///
/// ```xml
/// <?xml version="1.0"?>
/// <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
///     <name>{profile_name}</name>
///     <SSIDConfig>
///         <SSID>
///             <name>{ssid}</name>
///         </SSID>
///     </SSIDConfig>
///     <connectionType>ESS</connectionType>
///     <connectionMode>manual</connectionMode>
///     <MSM>
///         <security>
///             <authEncryption>
///                 <authentication>{auth}</authentication>
///                 <encryption>{encrypt}</encryption>
///                 <useOneX>false</useOneX>
///             </authEncryption>
///             {shared_key}
///         </security>
///     </MSM>
///     <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
///         <enableRandomization>false</enableRandomization>
///     </MacRandomization>
/// </WLANProfile>
/// ```
///
/// The placeholders `{profile_name}`, `{ssid}`, `{auth}`, `{encrypt}`, and `{shared_key}`
/// are dynamically populated based on the profile's properties.
///
/// # Notes
///
/// - The `to_xml` method includes a debug trace of the generated XML using [`rsutil::trace!`].
/// - The `shared_key` section is included only if the profile has a valid key and AKM type.
#[derive(Debug, Default, Clone, Eq, CopyGetters, Getters, WithSetters)]
pub struct Profile {
    #[cfg(target_os = "linux")]
    pub(crate) id: usize,
    #[getset(get_copy = "pub", set_with = "pub")]
    pub(crate) auth: AuthAlg,
    #[getset(get = "pub")]
    pub(crate) akm: Vec<AkmType>,
    #[getset(get_copy = "pub", set_with = "pub")]
    pub(crate) cipher: CipherType,
    #[getset(get = "pub")]
    pub(crate) ssid: String,
    #[getset(get = "pub", set_with = "pub")]
    pub(crate) bssid: Option<String>,
    #[getset(get = "pub", set_with = "pub")]
    pub(crate) key: Option<String>,
    #[cfg(target_os = "windows")]
    #[getset(get = "pub", set_with = "pub")]
    pub(crate) mode: crate::ConnectMode,
}

impl PartialEq for Profile {
    fn eq(&self, other: &Self) -> bool {
        self.ssid == other.ssid
    }
}

impl std::hash::Hash for Profile {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ssid.hash(state);
    }
}

impl Profile {
    #[inline]
    pub fn new<T: Into<String>>(ssid: T) -> Self {
        Self {
            ssid: ssid.into(),
            akm: vec![AkmType::None, ],
            ..Default::default()
        }
    }
    #[inline]
    pub fn add_akm(&mut self, akm_type: AkmType) {
        self.akm.push(akm_type);
    }

    #[cfg(target_os = "windows")]
    pub fn to_xml(&self) -> String {
        let profile_name = &self.ssid;
        let ssid = &self.ssid;
        let mode = self.mode.to_string();
        let flag = match self.akm.len() {
            0 | 1 => true,
            _ => self.akm.last().map(|&v| v == AkmType::None).unwrap_or_default()
        };
        let (auth, encrypt, shared_key) = if flag {
            (
                self.auth.to_string(),
                String::from("none"),
                Default::default(),
            )
        }
        else {
            (
                self.akm.last().unwrap_or(&AkmType::default()).to_string(),
                self.cipher.to_string(),
                format!(r#"
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>{}</protected>
                <keyMaterial>{}</keyMaterial>
            </sharedKey>"#, "false", match &self.key {
                    Some(v) => v,
                    None => "",
                })
            )
        };

        // !!!There must be no spaces or carriage returns before and after the xml string.
        let xml = format!(
r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{profile_name}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>{mode}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>{encrypt}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>{shared_key}
        </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
        <enableRandomization>false</enableRandomization>
    </MacRandomization>
</WLANProfile>"#, );
        rsutil::trace!("`{}`", xml);

        xml
    }
}


#[cfg(target_os = "windows")]
#[cfg(test)]
mod tests {
    use crate::{AkmType, AuthAlg, CipherType, ConnectMode};

    use super::Profile;

    #[test]
    fn test_to_xml() {
        let expect =
r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>TestSSID</name>
    <SSIDConfig>
        <SSID>
            <name>TestSSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>12345678</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
        <enableRandomization>false</enableRandomization>
    </MacRandomization>
</WLANProfile>"#;

        let ssid = "TestSSID";
        let key = "12345678";
        let mut profile = Profile::new(ssid)
            .with_mode(ConnectMode::Manual)
            .with_key(Some(key.into()))
            .with_auth(AuthAlg::Open)
            .with_cipher(CipherType::Ccmp);
        profile.add_akm(AkmType::Wpa2Psk);
        assert_eq!(profile.to_xml(), expect);

        let expect =
r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>TestSSID</name>
    <SSIDConfig>
        <SSID>
            <name>TestSSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
        <enableRandomization>false</enableRandomization>
    </MacRandomization>
</WLANProfile>"#;
        let ssid = "TestSSID";
        let profile = Profile::new(ssid);
        assert_eq!(profile.to_xml(), expect);
    }
}
