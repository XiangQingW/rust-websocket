//! Custom ip address setting

use std::collections::{HashMap, BTreeSet, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, IpAddr};
use std::sync::RwLock;
use url::Url;
use std::sync::{RwLockReadGuard, RwLockWriteGuard};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

/// ip fragment prefix
pub const IP_FRAGMENT_PREFIX: &str = "430BB5C318_ip:";

/// RW lock trait
trait RW<T> {
    fn write_lock(&self) -> RwLockWriteGuard<T>;
    fn read_lock(&self) -> RwLockReadGuard<T>;
}

impl<T> RW<T> for RwLock<T> {
    fn write_lock(&self) -> RwLockWriteGuard<T> {
        self.write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn read_lock(&self) -> RwLockReadGuard<T> {
        self.read().unwrap_or_else(|p| p.into_inner())
    }
}

/// addr source
#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub enum AddrSource {
    HttpDNS = 0,
    LocalDNS,
    HardCodeIp
}

/// sorted addr
#[derive(Debug, Eq, PartialEq, PartialOrd, Clone)]
pub struct SortedAddr {
    addr: IpAddr,
    is_rto: bool,
    source: AddrSource,
    connect_costs: Vec<i32>
}

impl Hash for SortedAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        state.finish();
    }
}

impl SortedAddr {
    pub fn new(addr: IpAddr, is_rto: bool, source: AddrSource) -> Self {
        SortedAddr {
            addr,
            is_rto,
            source,
            connect_costs: Vec::new()
        }
    }

    fn avg_cost(&self) -> i32 {
        if self.connect_costs.is_empty() {
            return std::i32::MAX;
        }

        let sum: i32 = self.connect_costs.iter().sum();
        sum / (self.connect_costs.len() as i32)
    }

    fn has_been_used(&self) -> bool {
        !self.connect_costs.is_empty()
    }

    fn delay_time(&self) -> i32 {
        if self.connect_costs.is_empty() {
            return 300;
        }

        std::cmp::min(600, self.avg_cost() + 250)
    }
}

impl Ord for SortedAddr {
    fn cmp(&self, other: &SortedAddr) -> Ordering {
        if self.addr == other.addr {
            return Ordering::Equal;
        }

        let self_avg_cost = self.avg_cost();
        let other_avg_cost = other.avg_cost();

        if self_avg_cost != other_avg_cost {
            return self_avg_cost.cmp(&other_avg_cost);
        }

        if self.is_rto != other.is_rto {
            return other.is_rto.cmp(&self.is_rto);
        }

        if self.source != other.source {
            return self.source.cmp(&other.source);
        }

        self.addr.cmp(&other.addr)
    }
}

lazy_static! {
	static ref CUSTOM_DOMAIN2ADDR: RwLock<HashMap<String, SocketAddr>> = {
		let h = HashMap::new();
		RwLock::new(h)
	};
	static ref CACHED_DOMAIN2ADDR: RwLock<HashMap<String, SocketAddr>> = {
		let h = HashMap::new();
		RwLock::new(h)
	};
	static ref CONNECTED_ADDR: RwLock<Option<SocketAddr>> = { RwLock::new(None) };

        static ref DOMAIN2SORTED_ADDRS: RwLock<HashMap<String, BTreeSet<SortedAddr>>> = {
            RwLock::new(HashMap::new())
        };
}

fn remove_old_domain_sorted_addrs(domain: &String, source: AddrSource) -> HashSet<SortedAddr> {
    let mut domain2addrs = DOMAIN2SORTED_ADDRS.write_lock();

    let addrs = match domain2addrs.get_mut(domain) {
        Some(addrs) => addrs,
        None => return HashSet::new(),
    };

    let removed_addrs: HashSet<SortedAddr> = addrs
        .iter()
        .filter(|a| a.source == source)
        .cloned()
        .collect();

    for addr in &removed_addrs {
        addrs.remove(addr);
    }

    removed_addrs
}

/// insert domain sorted addrs
pub fn insert_domain_sorted_addrs(domain: String, sorted_addrs: Vec<SortedAddr>, source: AddrSource) {
    let mut old_addrs = remove_old_domain_sorted_addrs(&domain, source);

    let mut domain2addrs = DOMAIN2SORTED_ADDRS.write_lock();
    let entry = domain2addrs.entry(domain.clone()).or_insert_with(BTreeSet::new);

    for addr in sorted_addrs {
        if let Some(old_addr) = old_addrs.take(&addr) {
            entry.insert(old_addr);
            continue;
        }

        let a = match entry.take(&addr) {
            Some(mut old_entry) => {
                old_entry.is_rto |= addr.is_rto;
                old_entry
            },
            None => addr,
        };
        entry.insert(a);
    }

    debug!("insert domain sorted addrs success: domain= {} entry= {:?} source= {:?}", domain, entry, source);
}

/// update domain sorted addr cost
pub fn update_domain_sorted_addr_cost(domain: &str, addr: IpAddr, cost_ms: i32) {
    let mut domain2addrs = DOMAIN2SORTED_ADDRS.write_lock();
    let addrs = match domain2addrs.get_mut(domain) {
        Some(addrs) => addrs,
        None => {
            warn!("domain sorted addr not found: domain= {}", domain);
            return;
        }
    };

    let mut sorted_addr = None;
    for a in addrs.iter() {
        if a.addr == addr {
            sorted_addr = Some(a.clone());
            break;
        }
    }

    let sorted_addr = match sorted_addr {
        Some(a) => a,
        None => {
            warn!("addr not found in sorted addrs: addr= {:?} addrs= {:?}", addr, addrs);
            return},
    };

    let mut addr = match addrs.take(&sorted_addr) {
        Some(a) => a,
        None => {
            warn!("take addr not found in sorted addrs: addr= {:?} addrs= {:?}", addr, addrs);
            return;
        }
    };
    addr.connect_costs.push(cost_ms);
    if 3 < addr.connect_costs.len() {
        addr.connect_costs.remove(0);
    }

    addrs.insert(addr);
    debug!("update domain sorted addr cost success: domain= {} cost_ms= {} addrs= {:?}", domain, cost_ms, addrs);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketAddrWithDelayTime {
    pub addr: SocketAddr,
    pub delay_time: i32
}

impl SocketAddrWithDelayTime {
    fn from_sorted_addr(sorted_addr: &SortedAddr, port: u16) -> Self {
        SocketAddrWithDelayTime {
            addr: SocketAddr::new(sorted_addr.addr.clone(), port),
            delay_time: sorted_addr.delay_time()
        }
    }

    fn new(addr: SocketAddr, delay_time: i32) -> Self {
        SocketAddrWithDelayTime {
            addr,
            delay_time
        }
    }
}

/// get sorted addrs
pub fn get_sorted_addrs(domain: &str, is_complex_conn: bool, first_addr: SocketAddr) -> Vec<SocketAddrWithDelayTime> {
    let port = first_addr.port();
    let first_addr = SocketAddrWithDelayTime::new(first_addr, 0);
    if !is_complex_conn {
        return vec![first_addr];
    }

    let domain2addrs = DOMAIN2SORTED_ADDRS.read_lock();

    let addrs = match domain2addrs.get(domain) {
        Some(addrs) => addrs,
        None => return vec![first_addr],
    };

    if addrs.is_empty() {
        return vec![first_addr];
    }

    let mut sorted_addrs = Vec::new();

    let fastest_addr = addrs.iter().nth(0).unwrap();
    sorted_addrs.push(SocketAddrWithDelayTime::from_sorted_addr(fastest_addr, port));

    if 1 < addrs.len() {
        let faster_addr = addrs.iter().nth(1).unwrap();
        sorted_addrs.push(SocketAddrWithDelayTime::from_sorted_addr(faster_addr, port));
    } else {
        sorted_addrs.push(sorted_addrs[0].clone());
    }

    fn has_selected(addrs: &[SocketAddrWithDelayTime], addr: &SortedAddr) -> bool {
        for a in addrs {
            if a.addr.ip() == addr.addr {
                return true;
            }
        }
        false
    }

    match addrs.iter().find(|a| !a.has_been_used() && !has_selected(&sorted_addrs, a)) {
        Some(a) => sorted_addrs.push(SocketAddrWithDelayTime::from_sorted_addr(a, port)),
        None => sorted_addrs.push(sorted_addrs[0].clone()),
    }

    let mut is_contain_first_addr = false;
    for addr in &sorted_addrs {
        if addr.addr == first_addr.addr {
            is_contain_first_addr = true;
            break;
        }
    }

    if !is_contain_first_addr {
        sorted_addrs.insert(0, first_addr);
        sorted_addrs.pop();
    }

    fn get_delay_time(delay_time: i32, min: i32, max: i32) -> i32 {
        let t = std::cmp::max(min, delay_time);
        std::cmp::min(max, t)
    }

    for (index, addr) in sorted_addrs.iter_mut().enumerate() {
        if index == 0 {
            addr.delay_time = 0;
            continue;
        }

        let factor = index as i32;
        addr.delay_time = get_delay_time(addr.delay_time * factor, 300 * factor, 600 * factor);
    }

    debug!("get sorted addrs: {:?}", sorted_addrs);
    sorted_addrs
}

/// set connected addr
pub fn set_connected_addr(addr: SocketAddr) {
	if let Ok(mut a) = CONNECTED_ADDR.write() {
		*a = Some(addr)
	}
}

/// get connected addr
pub fn get_connected_addr() -> Option<SocketAddr> {
	match CONNECTED_ADDR.read() {
		Ok(a) => a.as_ref().cloned(),
		Err(_) => None,
	}
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
pub fn remove_custom_addr(domain: &str) {
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
