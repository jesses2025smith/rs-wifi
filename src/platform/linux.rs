use nix::sys::{socket, stat};
use std::{collections::HashMap, os::{fd::AsRawFd, unix::io::OwnedFd}, path::{Path, PathBuf}};
use crate::{error::Error, Result};


const CTRL_IFACE_DIR: &'static str = "/var/run/wpa_supplicant";
const CTRL_IFACE_RETRY: usize = 3;
const REPLY_SIZE: usize = 4096;
const S_IFSOCK: stat::SFlag = stat::SFlag::S_IFSOCK;

fn remove_file(name: &str) -> Result<()> {
    if std::fs::exists(name) {
        let mode = stat::stat(name)
            .map_err(Into::<Error>::into)?   // TODO
            .st_mode;
        if stat::SFlag::from_bits_truncate(mode).contains(S_IFSOCK) {
            std::fs::remove_file(name)
                .map_err(Into::<Error>::into)?;
        }
    }

    Ok(())
}

#[derive(Debug)]
struct Context {
    socket: OwnedFd,
    sock_file: String,
    ctrl_iface: PathBuf,
}

#[derive(Debug)]
pub struct WifiUtil {
    root: PathBuf,
    connections: HashMap<String, Context>,
}

impl WifiUtil {
    #[inline]
    pub fn new() -> Result<Self> {
        let mut root = PathBuf::new();
        root.set_file_name(CTRL_IFACE_DIR);
        Ok(Self {
            root,
            ..Default::default()
        })
    }

    pub fn scan(&self, iface: &str) -> Result<()> {
        todo!()
    }

    pub fn scan_results(&self) -> Result<()> {
        todo!()
    }

    pub fn status(&self, iface: &str) -> Result<()> {
        // 0 => IFaceStatus::Connected,    // completed
        // 1 => IFaceStatus::Inactive,     // inactive
        // 2 => IFaceStatus::Connecting,   // authenticating
        // 3 => IFaceStatus::Connecting,   // associating
        // 4 => IFaceStatus::Connecting,   // associated
        // 5 => IFaceStatus::Connecting,   // associated
        // 6 => IFaceStatus::Connecting,   // group_handshake
        // 7 => IFaceStatus::Inactive,     // interface_disabled
        // 8 => IFaceStatus::Disconnected, // disconnected
        // 9 => IFaceStatus::Scanning,     // scanning
        todo!()
    }

    pub fn interfaces(&self) -> Result<Vec<String>> {
        let mut results = vec![];
        for entry in std::fs::read_dir(self.root.as_path())
            .map_err(Into::<Error>::into)? {
            let sock_file = entry.map_err(Into::<Error>::into)?
                .path();
            if sock_file.is_dir() {
                let mode = stat::stat(&sock_file)
                    .map_err(Into::<Error>::into)?   // TODO
                    .st_mode;
                if stat::SFlag::from_bits_truncate(mode).contains(S_IFSOCK) {
                    let pathname = sock_file.file_name()
                        .ok_or(Error::Other(format!("{:?} is no filename", sock_file).into()))?
                        .to_os_string()
                        .into_string()
                        .map_err(|e| Error::Other(e.into()))?;
                    // self.connections.insert(pathname, RawFd::from(mode));
                    results.push(pathname);
                }
            }
        }

        Ok(results)
    }

    fn _connect_to_wpas(&mut self, iface: &str) -> Result<()> {
        let ctrl_iface = self.root.join(&iface).as_path();
        if self.connections.contains_key(&iface) {
            commty::warn!("Connection for {} already exists!}", iface);
        }

        let sock_file = format!("/tmp/rswifi_{}.sock", iface);
        remove_file(&sock_file)?;

        let sock = socket::socket(
            socket::AddressFamily::Unix,
            socket::SockType::Datagram,
            socket::SockFlag::empty(), None
        )
            .map_err(Into::<Error>::into)?;
        let addr = socket::UnixAddr::new(sock_file.as_str())
            .map_err(Into::<Error>::into)?;
        socket::bind(sock.as_raw_fd(), &addr)
            .map_err(Into::<Error>::into)?;
        let addr = socket::UnixAddr::new(ctrl_iface)
            .map_err(Into::<Error>::into)?;
        socket::connect(sock.as_raw_fd(), &addr)
            .map_err(Into::<Error>::into)?;

        let len = socket::send(sock.as_raw_fd(), "PING".as_bytes(), socket::MsgFlags::empty())
            .map_err(Into::<Error>::into)?;
        commty::debug!("Sent PING: {}", len);
        for _ in 0..CTRL_IFACE_RETRY {
            let mut buffer = [0u8; REPLY_SIZE];
            let reply = socket::recv(sock.as_raw_fd(), &mut buffer, socket::MsgFlags::empty())
                .map_err(Into::<Error>::into)?;
            if reply == 0 {
                commty::error!("Connection to {} is broken!", iface);
                break
            }

            if String::from_utf8_lossy(&buffer[..reply]).starts_with("PONG") {
                commty::info!("Connection to socket {} successfully!", iface);
                self.connections.insert(
                    iface.to_string(), 
                    Context {
                        socket: sock,
                        sock_file,
                        ctrl_iface: ctrl_iface.into_path_buf(),
                    });
                break
            }
        }

        Ok(())
    }

    fn _send_cmd_to_wpas(&self, iface: &str, cmd: &str, get_repy: bool) -> Result<Option<String>> {
        if cmd.contains("psk") {
            commty::info!("Sending command: {} to wpa_s", cmd);
        }
        let ctx = self.connections.get(iface)
            .ok_or(Error::Other(format!("Unknown connection for {}", iface).into()))?;
        let fd = ctx.socket.as_raw_fd();
        let len = socket::send(fd, cmd.as_bytes(), socket::MsgFlags::empty())
            .map_err(Into::<Error>::into)?;
        commty::debug!("Sent command to wpa_s: {}", len);
        let mut buffer = [0u8; REPLY_SIZE];
        let reply = socket::recv(fd, &mut buffer, socket::MsgFlags::empty())
            .map_err(Into::<Error>::into)?;
        let result = String::from_utf8_lossy(&buffer[..reply]);
        if get_repy {
            return Ok(Some(result.to_string()));
        }

        if !result.eq_ignore_ascii_case("Ok\n") {
            commty::error!("Unexpected resp '{}' for Command '{}'", result, cmd);
        }

        Ok(None)
    }
}
