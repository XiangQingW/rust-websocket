//! Custom ip address setting

use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    static ref CUSTOM_DOMAIN2ADDR: RwLock<HashMap<String, SocketAddr>> = {
        let h = HashMap::new();
        RwLock::new(h)
    };
}

/// add custom addr-ip setting
pub fn set_custom_addr(domain: String, addr: &str) {
    if let Ok(mut addrs) = CUSTOM_DOMAIN2ADDR.write() {
        if let Ok(addr) = addr.parse::<Ipv4Addr>() {
            let addr = SocketAddrV4::new(addr, 443);
            let addr = SocketAddr::V4(addr);
            addrs.insert(domain, addr);
        }
    }
}

/// get custom addr-ip setting
pub fn try_get_custom_addr(domain: &str) -> Option<SocketAddr> {
    match CUSTOM_DOMAIN2ADDR.write() {
        Ok(addrs) => {
            let addr = addrs.get(domain).cloned();
            addr
        },
        _ => None,
    }
}

/// remove custom addr-ip setting
pub fn remove_custom_addr(domain: &str) {
    if let Ok(mut addrs) = CUSTOM_DOMAIN2ADDR.write() {
        addrs.remove(domain);
    }
}
