use cached::proc_macro::cached;
use cached::TimedSizedCache;
use log::{debug, warn};
#[cfg(feature = "quinn")]
use quinn::{Endpoint, Incoming};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;
use tokio::net::UdpSocket;

use crate::config::Certificates;
use crate::errors::DnsError;
use crate::message::Group;

pub enum SocketEndpoint
{
    Socket(UdpSocket),
    #[cfg(feature = "quinn")]
    QuicClient(Endpoint),
    #[cfg(feature = "quinn")]
    QuicServer(Incoming),
}

#[allow(irrefutable_let_patterns)]
impl SocketEndpoint
{
    pub fn socket(&self) -> Option<&UdpSocket>
    {
        if let Self::Socket(s) = self {
            return Some(s);
        }
        return None;
    }

    pub fn socket_consume(self) -> Option<UdpSocket>
    {
        if let Self::Socket(s) = self {
            return Some(s);
        }
        return None;
    }

    pub fn ip(&self) -> Option<IpAddr>
    {
        if let Self::Socket(s) = self {
            return s.local_addr().map(|s| s.ip().clone()).ok();
        }
        return None;
    }

    #[cfg(feature = "quinn")]
    pub fn client_consume(self) -> Option<Endpoint>
    {
        if let Self::QuicClient(s) = self {
            return Some(s);
        }
        return None;
    }

    #[cfg(feature = "quinn")]
    pub fn server(&mut self) -> Option<&mut Incoming>
    {
        if let Self::QuicServer(s) = self {
            return Some(s);
        }
        return None;
    }
}

#[derive(Debug, Clone)]
pub enum Protocol
{
    Basic,
    #[cfg(feature = "frames")]
    Frames,
    #[cfg(feature = "quic")]
    Quic(Certificates),
}

impl Protocol
{
    pub fn requires_public_key(&self) -> bool
    {
        #[cfg(feature = "quic")]
        {
            return if let Self::Quic(_) = self {
                true
            } else {
                false
            };
        }
        return false;
    }
}

impl fmt::Display for Protocol
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", self)
    }
}

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(1000, 3600) }",
    type = "TimedSizedCache<String, Result<SocketAddr, DnsError>>",
    convert = r#"{ format!("{}", host) }"#
)]
pub async fn to_socket(host: &str) -> Result<SocketAddr, DnsError>
{
    let to_err = |e| {
        DnsError::Failed(format!(
            "Unable to retrieve ip for {}. Message: {}",
            host, e
        ))
    };
    for addr in lookup_host(host).await.map_err(to_err)? {
        return Ok(addr);
    }
    return Err(DnsError::Failed(format!(
        "Unable to retrieve ip for {}",
        host
    )));
}

pub struct Multicast
{
    cache: HashMap<IpAddr, bool>,
}

impl Multicast
{
    pub fn new() -> Self
    {
        return Multicast {
            cache: HashMap::new(),
        };
    }

    pub fn join_group(
        &mut self,
        sock: &UdpSocket,
        interface_addr: &IpAddr,
        remote_ip: &IpAddr,
    ) -> bool
    {
        if self.cache.contains_key(&interface_addr) {
            warn!("Ipv6 multicast not supported");
            return false;
        }
        let interface_ipv4 = match interface_addr {
            IpAddr::V4(ipv4) => ipv4,
            _ => {
                warn!("Ipv6 multicast not supported");
                return false;
            }
        };

        let op = match remote_ip {
            IpAddr::V4(multicast_ipv4) => {
                sock.set_multicast_loop_v4(false).unwrap_or(());
                sock.join_multicast_v4(multicast_ipv4.clone(), interface_ipv4.clone())
            }
            _ => {
                warn!("Ipv6 multicast not supported");
                return false;
            }
        };
        if let Err(_) = op {
            warn!("Unable to join multicast network");
            return false;
        } else {
            debug!("Joined multicast {}", remote_ip);
            self.cache.insert(remote_ip.clone(), true);
            return true;
        }
    }

    pub async fn join_groups(&mut self, sock: &UdpSocket, groups: &[Group], local_addr: &IpAddr)
    {
        for group in groups {
            for remote_host in &group.allowed_hosts {
                let addr = match to_socket(remote_host).await {
                    Ok(a) => a,
                    _ => {
                        warn!("Unable to parse or retrieve address for {}", remote_host);
                        continue;
                    }
                };
                if addr.ip().is_multicast() {
                    self.join_group(sock, local_addr, &addr.ip());
                }
            }
        }
    }
}
