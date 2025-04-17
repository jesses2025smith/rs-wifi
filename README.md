# rswifi
Cross-platform wireless network (WiFi) management

## Features
- Scan for available WiFi networks
- Connect to a WiFi network
- Disconnect from a WiFi network
- Retrieve connection status
- Cross-platform support (Windows, Linux)

## Installation
To use `rswifi`, add it to your `Cargo.toml`:
```toml
[dependencies]
rswifi = "0.1"
```

## Usage
Here is a basic example:
```rust
use rswifi::{AkmType, AuthAlg, CipherType, Error, IFaceStatus, Profile, Result, WifiUtil};

fn main() -> Result<()> {
    let util = WifiUtil::new()?;
    let ifaces = util.interfaces()?;
    let iface = ifaces.first()
        .ok_or(Error::Other("No iface found".into()))?;

    // Disconnect
    iface.disconnect()?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let status = iface.status()?;
    assert_eq!(status, IFaceStatus::Disconnected);

    // Add Profle
    let ssid = "TestSSID";
    let key = "12345678";
    let mut profile = Profile::new(ssid)
        .with_key(Some(key.into()))
        .with_auth(AuthAlg::Open)
        .with_cipher(CipherType::Ccmp);
    profile.add_akm(AkmType::Wpa2Psk);
    iface.add_network_profile(&profile)?;

    // Scan
    iface.scan()?;
    std::thread::sleep(std::time::Duration::from_secs(5));
    let results = iface.scan_results()?;
    println!("{:?}", results);

    // Connect
    let ret = iface.connect("TestSSID")?;
    assert!(ret);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let status = iface.status()?;
    assert_eq!(status, IFaceStatus::Connected);

    // Remove Profile
    iface.remove_network_profile(&ssid)?;

    // Get Profile names
    let results = iface.network_profile_name_list()?;
    println!("{:?}", results);

    Ok(())
}
```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
