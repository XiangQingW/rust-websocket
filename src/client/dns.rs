//! Custom ip address setting

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::RwLock;
use url::Url;

/// ip fragment prefix
pub const IP_FRAGMENT_PREFIX: &str = "430BB5C318_ip:";

lazy_static! {
	static ref CUSTOM_DOMAIN2ADDR: RwLock<HashMap<String, SocketAddr>> = {
		let h = HashMap::new();
		RwLock::new(h)
	};
	static ref CACHED_DOMAIN2ADDR: RwLock<HashMap<String, SocketAddr>> = {
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
		}
		_ => None,
	}
}

/// remove custom addr-ip setting
pub fn remove_custom_add(domain: &str) {
	if let Ok(mut addrs) = CUSTOM_DOMAIN2ADDR.write() {
		addrs.remove(domain);
	}
}

/// cache addr
pub fn cache_addr(domain: String, addr: SocketAddr) {
	if let Ok(mut addrs) = CACHED_DOMAIN2ADDR.write() {
		debug!(
			"cache websocket addr: domain= {:?} addr= {:?}",
			domain, addr
		);
		addrs.insert(domain, addr);
	}
}

/// try get cached addr
pub fn try_get_cached_addr(domain: &str) -> Option<SocketAddr> {
	match CACHED_DOMAIN2ADDR.write() {
		Ok(addrs) => {
			let addr = addrs.get(domain).cloned();
			addr
		}
		_ => None,
	}
}

/// get addrs by url
pub(crate) fn get_addrs_by_url(url: &Url) -> Option<SocketAddr> {
	let fragment = url.fragment()?;

	if !fragment.starts_with(IP_FRAGMENT_PREFIX) {
		return None;
	}

	let elements: Vec<_> = fragment.split(':').collect();
	let ip = elements.get(1)?;

	let port = if url.scheme() == "ws" { 80 } else { 443 };

	get_addr_by_ip(ip, port)
}

/// get addr by ip
fn get_addr_by_ip(ip: &str, port: u16) -> Option<SocketAddr> {
	match ip.parse::<Ipv4Addr>() {
		Ok(addr) => {
			let addr = SocketAddrV4::new(addr, port);
			let addr = SocketAddr::V4(addr);
			Some(addr)
		}
		Err(err) => {
			warn!("get addr by ip failed: err= {:?} ip= {:?}", err, ip);
			None
		}
	}
}
