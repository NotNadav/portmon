//! Socket enumeration: list every TCP/UDP socket, map each to its owning
//! process, label well-known ports, and reverse-resolve remote IPs off the
//! UI thread.
//!
//! Windows: netstat2 wraps GetExtendedTcp/UdpTable, which give the owning PID
//! per socket; sysinfo turns that PID into a name.

use dns_lookup::lookup_addr;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use sysinfo::{Pid, ProcessesToUpdate, System};

/// One row in the table: a single socket and who owns it.
#[derive(Clone)]
pub struct Conn {
    pub proto: String,             // "TCP", "UDP", or "UDP·QUIC?" (heuristic)
    pub local: String,             // local ip:port
    pub remote: String,            // remote ip:port ("—" for UDP / not connected)
    pub remote_ip: Option<IpAddr>, // remote ip alone, for reverse-DNS (None if n/a)
    pub remote_port: u16,          // remote port, to rebuild "host:port" after DNS
    pub service: String,           // well-known service for the port, e.g. "https"
    pub state: String,             // TCP state; "—" for UDP
    pub pid: u32,
    pub process: String,
    pub listening: bool,           // TCP socket in LISTEN state
    pub key: String,               // stable identity for new-connection diffing
}

/// Well-known port to service name.
fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 465 | 587 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        110 | 995 => "pop3",
        123 => "ntp",
        135 => "msrpc",
        137 | 138 | 139 => "netbios",
        143 | 993 => "imap",
        161 | 162 => "snmp",
        389 | 636 => "ldap",
        443 => "https",
        445 => "smb",
        1433 => "mssql",
        1521 => "oracle",
        1883 | 8883 => "mqtt",
        2049 => "nfs",
        3000 => "dev",
        3306 => "mysql",
        3389 => "rdp",
        5173 => "vite",
        5353 => "mdns",
        5432 => "postgres",
        5672 => "amqp",
        5900 => "vnc",
        6379 => "redis",
        8080 | 8000 => "http-alt",
        8443 => "https-alt",
        9200 => "elastic",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "",
    }
}

/// Snapshot all current sockets. Cheap enough to run on the UI thread.
/// sys is reused across calls so process info stays warm.
pub fn gather(sys: &mut System) -> Vec<Conn> {
    // Refresh the PID->name map first so new processes resolve.
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets = match get_sockets_info(af, proto) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::with_capacity(sockets.len());
    for si in sockets {
        // A socket can have several PIDs; show the first.
        let pid = si.associated_pids.first().copied().unwrap_or(0);
        let process = if pid == 0 {
            "—".to_string()
        } else {
            sys.process(Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| "—".to_string())
        };

        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) => {
                let listening = matches!(t.state, TcpState::Listen);
                let connected = t.remote_port != 0 && !t.remote_addr.is_unspecified();
                // Use the well-known side: remote port if connected, else local.
                let svc_port = if connected { t.remote_port } else { t.local_port };
                let local = format!("{}:{}", t.local_addr, t.local_port);
                let remote = if connected {
                    format!("{}:{}", t.remote_addr, t.remote_port)
                } else {
                    "—".into()
                };
                out.push(Conn {
                    key: format!("TCP|{local}|{remote}|{pid}"),
                    proto: "TCP".into(),
                    local,
                    remote,
                    remote_ip: if connected { Some(t.remote_addr) } else { None },
                    remote_port: t.remote_port,
                    service: service_name(svc_port).into(),
                    state: format!("{:?}", t.state),
                    pid,
                    process,
                    listening,
                });
            }
            ProtocolSocketInfo::Udp(u) => {
                // QUIC rides on UDP with no socket-level flag, so guess by port.
                // The "?" makes clear it's a guess, not a fact.
                let quic_guess = u.local_port == 443 || u.local_port == 80;
                let local = format!("{}:{}", u.local_addr, u.local_port);
                out.push(Conn {
                    key: format!("UDP|{local}|{pid}"),
                    proto: if quic_guess { "UDP·QUIC?".into() } else { "UDP".into() },
                    local,
                    remote: "—".into(),
                    remote_ip: None,
                    remote_port: 0,
                    service: service_name(u.local_port).into(),
                    state: "—".into(),
                    pid,
                    process,
                    listening: false,
                });
            }
        }
    }
    out
}

/// Lazy, non-blocking reverse-DNS cache. host() returns a cached name, or kicks
/// off a background lookup and returns None for now, so the UI never blocks.
#[derive(Clone, Default)]
pub struct Resolver {
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    inflight: Arc<Mutex<HashSet<IpAddr>>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cached hostname, or None while a background lookup runs.
    pub fn host(&self, ip: IpAddr) -> Option<String> {
        if ip.is_loopback() || ip.is_unspecified() {
            return None;
        }
        if let Some(entry) = self.cache.lock().unwrap().get(&ip) {
            return entry.clone();
        }
        if self.inflight.lock().unwrap().insert(ip) {
            let cache = self.cache.clone();
            let inflight = self.inflight.clone();
            std::thread::spawn(move || {
                // With no PTR record, lookup_addr echoes the IP; treat that as no name.
                let name = lookup_addr(&ip).ok().filter(|n| n != &ip.to_string());
                cache.lock().unwrap().insert(ip, name);
                inflight.lock().unwrap().remove(&ip);
            });
        }
        None
    }
}
