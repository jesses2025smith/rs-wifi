mod interface;
mod util;

pub use interface::Interface;

use nix::sys::stat;
use std::path::PathBuf;
use crate::{error::Error, Result};


const CTRL_IFACE_DIR: &str = "/var/run/wpa_supplicant";

#[derive(Debug)]
pub struct WifiUtil {
    root: PathBuf,
}

impl WifiUtil {
    #[inline]
    pub fn new() -> Result<Self> {
        let mut root = PathBuf::new();
        root.set_file_name(CTRL_IFACE_DIR);
        Ok(Self {
            root,
        })
    }

    pub fn interfaces(&self) -> Result<Vec<Interface>> {
        let mut results = vec![];
        for entry in std::fs::read_dir(self.root.as_path())
            .map_err(Into::<Error>::into)? {
            let ctrl_iface = entry.map_err(Into::<Error>::into)?
                .path();

            let mode = stat::stat(&ctrl_iface)
                    .map_err(Into::<Error>::into)?
                    .st_mode;
            if stat::SFlag::from_bits_truncate(mode).contains(util::S_IFSOCK) {
                if let Some(iface) = Interface::new(ctrl_iface)? {
                    results.push(iface);
                }
            }
        }

        Ok(results)
    }
}

