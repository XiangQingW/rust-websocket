use bytes::BufMut;
use futures::{Future, Poll};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio_io::{AsyncRead, AsyncWrite};

pub(super) fn try_parse(host: &str, port: u16) -> Option<SocketAddr> {
	if let Ok(addr) = host.parse::<Ipv4Addr>() {
		let addr = SocketAddrV4::new(addr, port);
		return Some(SocketAddr::V4(addr));
	}
	if let Ok(addr) = host.parse::<Ipv6Addr>() {
		let addr = SocketAddrV6::new(addr, port, 0, 0);
		return Some(SocketAddr::V6(addr));
	}

	None
}

pub(super) fn tunnel<T>(conn: T, host: String, port: u16) -> Tunnel<T> {
	let mut buf = format!(
		"\
		 CONNECT {0}:{1} HTTP/1.1\r\n\
		 Host: {0}:{1}\r\n\
		 ",
		host, port
	)
	.into_bytes();

	// headers end
	buf.extend_from_slice(b"\r\n");

	Tunnel {
		buf: io::Cursor::new(buf),
		conn: Some(conn),
		state: TunnelState::Writing,
	}
}

pub(super) struct Tunnel<T> {
	buf: io::Cursor<Vec<u8>>,
	conn: Option<T>,
	state: TunnelState,
}

enum TunnelState {
	Writing,
	Reading,
}

impl<T> Future for Tunnel<T>
where
	T: AsyncRead + AsyncWrite,
{
	type Item = T;
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		loop {
			if let TunnelState::Writing = self.state {
				let n = try_ready!(self.conn.as_mut().unwrap().write_buf(&mut self.buf));
				if !self.buf.has_remaining_mut() {
					self.state = TunnelState::Reading;
					self.buf.get_mut().truncate(0);
				} else if n == 0 {
					return Err(tunnel_eof());
				}
			} else {
				let n = try_ready!(self
					.conn
					.as_mut()
					.unwrap()
					.read_buf(&mut self.buf.get_mut()));
				let read = &self.buf.get_ref()[..];
				if n == 0 {
					return Err(tunnel_eof());
				} else if read.len() > 12 {
					if read.starts_with(b"HTTP/1.1 200") || read.starts_with(b"HTTP/1.0 200") {
						if read.ends_with(b"\r\n\r\n") {
							return Ok(self.conn.take().unwrap().into());
						}
					// else read more
					} else if read.starts_with(b"HTTP/1.1 407") {
						return Err(io::Error::new(
							io::ErrorKind::Other,
							"proxy authentication required",
						));
					} else {
						return Err(io::Error::new(io::ErrorKind::Other, "unsuccessful tunnel"));
					}
				}
			}
		}
	}
}

#[inline]
fn tunnel_eof() -> io::Error {
	io::Error::new(
		io::ErrorKind::UnexpectedEof,
		"unexpected eof while tunneling",
	)
}
