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
