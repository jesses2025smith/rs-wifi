#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
pub use win::*;
#[cfg(target_os = "macos")]
mod osx;
#[cfg(target_os = "macos")]
pub use osx::*;

use crate::{IFaceStatus, Profile, Result};
use std::collections::HashSet;

pub trait WiFiInterface {
    fn scan(&self) -> Result<()>;
    fn scan_results(&self) -> Result<HashSet<Profile>>;
    fn connect(&self, ssid: &str) -> Result<bool>;
    fn disconnect(&self) -> Result<()>;
    fn add_network_profile(&self, profile: &Profile) -> Result<()>;
    fn network_profile_name_list(&self) -> Result<Vec<String>>;
    fn network_profiles(&self) -> Result<Vec<Profile>>;
    fn remove_network_profile(&self, name: &str) -> Result<()>;
    fn remove_all_network_profiles(&self) -> Result<()>;
    fn status(&self) -> Result<IFaceStatus>;
}
