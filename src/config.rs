use crate::iface::Mode;
use serde::{Deserialize, Serialize};


pub const ETHERNET_HEADER_SIZE:u32 = 14;
pub const ZERO_MAC_ADDRESS:&str = "00:00:00:00:00:00";
pub const RC4_KEY:&str = "zec1tb@2o2o(#$)";


#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum ProtocolMode {
    Udp,
    Tcp
}


#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum RunMode {
    #[serde(alias = "client")]
    Client,
    #[serde(alias = "server")]
    Server
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub pid: Option<String>,
    pub is_daemon: Option<bool>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub tap_mode: Mode,
    pub mtu: Option<u32>,
    pub nics: Vec<NicConfig>,
    pub run_mode: RunMode,
    pub reply_arp: Option<bool>,
    pub server: ServerConfig,
    pub protocol: Option<ProtocolMode>,
    pub log: Option<String>,
    pub timeout: Option<u64>,
    pub use_remote_config: Option<bool>,
    pub client_tap_mode: Option<Mode>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub script_path: Option<String>,
    pub script_content: Option<String>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NicConfig {
    pub ifname: String,
    pub ip: String,
    pub mac: String
}
