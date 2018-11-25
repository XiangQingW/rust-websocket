//! Contains the WebSocket client.
use std::io::Result as IoResult;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::{self, FromStr};

use http::header::HeaderMap;
use http::header::{SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL};
use std::io::BufReader;

use dataframe::DataFrame;
use message::OwnedMessage;
pub use receiver::Reader;
use receiver::Receiver;
use result::WebSocketResult;
use sender::Sender;
pub use sender::Writer;
use stream::sync::{AsTcpStream, Shutdown, Splittable, Stream};
use ws;
use ws::dataframe::DataFrame as DataFrameable;
use ws::receiver::Receiver as ReceiverTrait;
use ws::receiver::{DataFrameIterator, MessageIterator};
use ws::sender::Sender as SenderTrait;

use header::sec_websocket_extensions::Extension;

/// Represents a WebSocket client, which can send and receive messages/data frames.
///
/// The client just wraps around a `Stream` (which is something that can be read from
/// and written to) and handles the websocket protocol. TCP or SSL over TCP is common,
/// but any stream can be used.
///
/// A `Client` can also be split into a `Reader` and a `Writer` which can then be moved
/// to different threads, often using a send loop and receiver loop concurrently,
/// as shown in the client example in `examples/client.rs`.
/// This is only possible for streams that implement the `Splittable` trait, which
/// currently is only TCP streams. (it is unsafe to duplicate an SSL stream)
///
///# Connecting to a Server
///
///```no_run
///extern crate websocket;
///# fn main() {
///
///use websocket::{ClientBuilder, Message};
///
///let mut client = ClientBuilder::new("ws://127.0.0.1:1234")
///    .unwrap()
///    .connect_insecure()
///    .unwrap();
///
///let message = Message::text("Hello, World!");
///client.send_message(&message).unwrap(); // Send message
///# }
///```
pub struct Client<S>
where
    S: Stream,
{
    stream: BufReader<S>,
    headers: HeaderMap,
    sender: Sender,
    receiver: Receiver,
}

impl Client<TcpStream> {
    /// Shuts down the sending half of the client connection, will cause all pending
    /// and future IO to return immediately with an appropriate value.
    pub fn shutdown_sender(&self) -> IoResult<()> {
        self.stream.get_ref().as_tcp().shutdown(Shutdown::Write)
    }

    /// Shuts down the receiving half of the client connection, will cause all pending
    /// and future IO to return immediately with an appropriate value.
    pub fn shutdown_receiver(&self) -> IoResult<()> {
        self.stream.get_ref().as_tcp().shutdown(Shutdown::Read)
    }
}

impl<S> Client<S>
where
    S: AsTcpStream + Stream,
{
    /// Shuts down the client connection, will cause all pending and future IO to
    /// return immediately with an appropriate value.
    pub fn shutdown(&self) -> IoResult<()> {
        self.stream.get_ref().as_tcp().shutdown(Shutdown::Both)
    }

    /// See [`TcpStream::peer_addr`]
    /// (https://doc.rust-lang.org/std/net/struct.TcpStream.html#method.peer_addr).
    pub fn peer_addr(&self) -> IoResult<SocketAddr> {
        self.stream.get_ref().as_tcp().peer_addr()
    }

    /// See [`TcpStream::local_addr`]
    /// (https://doc.rust-lang.org/std/net/struct.TcpStream.html#method.local_addr).
    pub fn local_addr(&self) -> IoResult<SocketAddr> {
        self.stream.get_ref().as_tcp().local_addr()
    }

    /// See [`TcpStream::set_nodelay`]
    /// (https://doc.rust-lang.org/std/net/struct.TcpStream.html#method.set_nodelay).
    pub fn set_nodelay(&mut self, nodelay: bool) -> IoResult<()> {
        self.stream.get_ref().as_tcp().set_nodelay(nodelay)
    }

    /// Changes whether the stream is in nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> IoResult<()> {
        self.stream.get_ref().as_tcp().set_nonblocking(nonblocking)
    }
}

impl<S> Client<S>
where
    S: Stream,
{
    /// Creates a Client from a given stream
    /// **without sending any handshake** this is meant to only be used with
    /// a stream that has a websocket connection already set up.
    /// If in doubt, don't use this!
    #[doc(hidden)]
    pub fn unchecked(
        stream: BufReader<S>,
        headers: HeaderMap,
        out_mask: bool,
        in_mask: bool,
    ) -> Self {
        Client {
            headers: headers,
            stream: stream,
            sender: Sender::new(out_mask),    // true
            receiver: Receiver::new(in_mask), // false
        }
    }

    /// Sends a single data frame to the remote endpoint.
    pub fn send_dataframe<D>(&mut self, dataframe: &D) -> WebSocketResult<()>
    where
        D: DataFrameable,
    {
        self.sender.send_dataframe(self.stream.get_mut(), dataframe)
    }

    /// Sends a single message to the remote endpoint.
    pub fn send_message<M>(&mut self, message: &M) -> WebSocketResult<()>
    where
        M: ws::Message,
    {
        self.sender.send_message(self.stream.get_mut(), message)
    }

    /// Reads a single data frame from the remote endpoint.
    pub fn recv_dataframe(&mut self) -> WebSocketResult<DataFrame> {
        self.receiver.recv_dataframe(&mut self.stream)
    }

    /// Returns an iterator over incoming data frames.
    pub fn incoming_dataframes(&mut self) -> DataFrameIterator<Receiver, BufReader<S>> {
        self.receiver.incoming_dataframes(&mut self.stream)
    }

    /// Reads a single message from this receiver.
    ///
    /// ```rust,no_run
    /// use websocket::{ClientBuilder, Message};
    /// let mut client = ClientBuilder::new("ws://localhost:3000")
    ///     .unwrap()
    ///     .connect_insecure()
    ///     .unwrap();
    ///
    /// client.send_message(&Message::text("Hello world!")).unwrap();
    ///
    /// let response = client.recv_message().unwrap();
    /// ```
    pub fn recv_message(&mut self) -> WebSocketResult<OwnedMessage> {
        self.receiver.recv_message(&mut self.stream)
    }

    /// Access the headers that were sent in the server's handshake response.
    /// This is a catch all for headers other than protocols and extensions.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// **If you supplied a protocol, you must check that it was accepted by
    /// the server** using this function.
    /// This is not done automatically because the terms of accepting a protocol
    /// can get complicated, especially if some protocols depend on others, etc.
    ///
    /// ```rust,no_run
    /// # use websocket::ClientBuilder;
    /// let mut client = ClientBuilder::new("wss://test.fysh.in").unwrap()
    ///     .add_protocols(vec!["xmpp"])
    ///     .connect_insecure()
    ///     .unwrap();
    ///
    /// // be sure to check the protocol is there!
    /// assert!(client.protocols().iter().any(|p| p as &str == "xmpp"));
    /// ```
    pub fn protocols<'a>(&'a self) -> Vec<&str> {
        self.headers
            .get(SEC_WEBSOCKET_PROTOCOL)
            .map(|e| {
                str::from_utf8(e.as_bytes())
                    .unwrap()
                    .split(',')
                    .filter_map(|x| match x.trim() {
                        "" => None,
                        y => Some(y),
                    }).collect::<Vec<&str>>()
            }).unwrap_or(vec![])
    }

    /// If you supplied a protocol, be sure to check if it was accepted by the
    /// server here. Since no extensions are implemented out of the box yet, using
    /// one will require its own implementation.
    pub fn extensions(&self) -> Vec<Extension> {
        self.headers
            .get(SEC_WEBSOCKET_EXTENSIONS)
            .map(|e| {
                str::from_utf8(e.as_bytes())
                    .unwrap()
                    .split(',')
                    .filter_map(|x| match x.trim() {
                        "" => None,
                        y => Some(y),
                    }).filter_map(|x| match Extension::from_str(x) {
                        Ok(ext) => Some(ext),
                        _ => None,
                    }).collect::<Vec<Extension>>()
            }).unwrap_or(vec![])
    }

    /// Get a reference to the stream.
    /// Useful to be able to set options on the stream.
    ///
    /// ```rust,no_run
    /// # use websocket::ClientBuilder;
    /// let mut client = ClientBuilder::new("ws://double.down").unwrap()
    ///     .connect_insecure()
    ///     .unwrap();
    ///
    /// client.stream_ref().set_ttl(60).unwrap();
    /// ```
    pub fn stream_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get a handle to the writable portion of this stream.
    /// This can be used to write custom extensions.
    ///
    /// ```rust,no_run
    /// # use websocket::ClientBuilder;
    /// use websocket::Message;
    /// use websocket::ws::sender::Sender as SenderTrait;
    /// use websocket::sender::Sender;
    ///
    /// let mut client = ClientBuilder::new("ws://the.room").unwrap()
    ///     .connect_insecure()
    ///     .unwrap();
    ///
    /// let message = Message::text("Oh hi, Mark.");
    /// let mut sender = Sender::new(true);
    /// let mut buf = Vec::new();
    ///
    /// sender.send_message(&mut buf, &message);
    ///
    /// /* transform buf somehow */
    ///
    /// client.writer_mut().write_all(&buf);
    /// ```
    pub fn writer_mut(&mut self) -> &mut Write {
        self.stream.get_mut()
    }

    /// Get a handle to the readable portion of this stream.
    /// This can be used to transform raw bytes before they
    /// are read in.
    ///
    /// ```rust,no_run
    /// # use websocket::ClientBuilder;
    /// use std::io::Cursor;
    /// use websocket::ws::receiver::Receiver as ReceiverTrait;
    /// use websocket::receiver::Receiver;
    ///
    /// let mut client = ClientBuilder::new("ws://the.room").unwrap()
    ///     .connect_insecure()
    ///     .unwrap();
    ///
    /// let mut receiver = Receiver::new(false);
    /// let mut buf = Vec::new();
    ///
    /// client.reader_mut().read_to_end(&mut buf);
    ///
    /// /* transform buf somehow */
    ///
    /// let mut buf_reader = Cursor::new(&mut buf);
    /// let message = receiver.recv_message(&mut buf_reader).unwrap();
    /// ```
    pub fn reader_mut(&mut self) -> &mut Read {
        &mut self.stream
    }

    /// Deconstruct the client into its underlying stream and
    /// maybe some of the buffer that was already read from the stream.
    /// The client uses a buffered reader to read in messages, so some
    /// bytes might already be read from the stream when this is called,
    /// these buffered bytes are returned in the form
    ///
    /// `(byte_buffer: Vec<u8>, buffer_capacity: usize, buffer_position: usize)`
    pub fn into_stream(self) -> (S, Option<(Vec<u8>,)>) {
        let stream = self.stream.into_inner();
        (stream, None)
    }

    /// Returns an iterator over incoming messages.
    ///
    ///```no_run
    ///# extern crate websocket;
    ///# fn main() {
    ///use websocket::ClientBuilder;
    ///
    ///let mut client = ClientBuilder::new("ws://127.0.0.1:1234").unwrap()
    ///                     .connect(None).unwrap();
    ///
    ///for message in client.incoming_messages() {
    ///    println!("Recv: {:?}", message.unwrap());
    ///}
    ///# }
    ///```
    ///
    /// Note that since this method mutably borrows the `Client`, it may be necessary to
    /// first `split()` the `Client` and call `incoming_messages()` on the returned
    /// `Receiver` to be able to send messages within an iteration.
    ///
    ///```no_run
    ///# extern crate websocket;
    ///# fn main() {
    ///use websocket::ClientBuilder;
    ///
    ///let mut client = ClientBuilder::new("ws://127.0.0.1:1234").unwrap()
    ///                     .connect_insecure().unwrap();
    ///
    ///let (mut receiver, mut sender) = client.split().unwrap();
    ///
    ///for message in receiver.incoming_messages() {
    ///    // Echo the message back
    ///    sender.send_message(&message.unwrap()).unwrap();
    ///}
    ///# }
    ///```
    pub fn incoming_messages<'a>(&'a mut self) -> MessageIterator<'a, Receiver, BufReader<S>> {
        self.receiver.incoming_messages(&mut self.stream)
    }
}

impl<S> Client<S>
where
    S: Splittable + Stream,
{
    /// Split this client into its constituent Sender and Receiver pair.
    ///
    /// This allows the Sender and Receiver to be sent to different threads.
    ///
    ///```no_run
    ///# extern crate websocket;
    ///# fn main() {
    ///use std::thread;
    ///use websocket::{ClientBuilder, Message};
    ///
    ///let mut client = ClientBuilder::new("ws://127.0.0.1:1234").unwrap()
    ///                     .connect_insecure().unwrap();
    ///
    ///let (mut receiver, mut sender) = client.split().unwrap();
    ///
    ///thread::spawn(move || {
    ///    for message in receiver.incoming_messages() {
    ///        println!("Recv: {:?}", message.unwrap());
    ///    }
    ///});
    ///
    ///let message = Message::text("Hello, World!");
    ///sender.send_message(&message).unwrap();
    ///# }
    ///```
    pub fn split(
        self,
    ) -> IoResult<(
        Reader<<S as Splittable>::Reader>,
        Writer<<S as Splittable>::Writer>,
    )> {
        let stream = self.stream.into_inner();
        let (read, write) = stream.split()?;
        Ok((
            Reader {
                stream: BufReader::new(read),
                receiver: self.receiver,
            },
            Writer {
                stream: write,
                sender: self.sender,
            },
        ))
    }
}
