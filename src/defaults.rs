use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const BIND_ADDRESS: &str = "0.0.0.0:8900";
pub const SEND_ADDRESS: &str = "0.0.0.0:8901";
pub const DEFAULT_GROUP: &str = "default";
pub const CLIPBOARD_NAME: &str = "clipboard";
pub const DEFAULT_CLIPBOARD: &str = CLIPBOARD_NAME;
pub const DEFAULT_PROTOCOL: &str = "basic";
pub const PACKAGE_NAME: &str = "clipboard-sync";
pub const DEFAULT_ALLOWED_HOST: &str = "224.0.0.89:8900";
pub const MAX_CHANNEL: usize = 100;
pub const KEY_SIZE: usize = 32;
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_RECEIVE_BUFFER: usize = 50 * 1024 * 1024;
pub const MAX_UDP_BUFFER: usize = 65535;
pub const MAX_PACKET: usize = 512;
pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const QUIC_STREAM: u8 = 0;
pub const CONNECTION_TIMEOUT: u64 = 2000;
pub const DATA_TIMEOUT: u64 = 5000;
pub const RECEIVE_ONCE_WAIT: u64 = 45; //seconds

pub fn default_socket_send_address() -> SocketAddr
{
    return SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
}

pub fn default_allowed_host() -> String
{
    return DEFAULT_ALLOWED_HOST.to_owned();
}

pub fn default_allowed_hosts() -> Vec<String>
{
    return vec![default_allowed_host()];
}

pub fn default_clipboard() -> String
{
    return DEFAULT_CLIPBOARD.to_owned();
}
