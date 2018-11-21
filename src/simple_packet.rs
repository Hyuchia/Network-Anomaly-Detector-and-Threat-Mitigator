extern crate chrono;
extern crate colored;

use simple_packet::chrono::prelude::*;
use simple_packet::colored::*;

use port::*;

use std::fmt;

/// Simple Packet
/// 
/// This is a very simple representation of all the information we get from
/// all of the packets received. It allows us to centralize data and keep a
/// consistent structure.
/// 
pub struct SimplePacket <'a> {
	pub category: &'a str,
	pub interface: String,
	pub source_address: String,
	pub source_port: u16,
	pub source_port_description: &'a str,
	pub destination_address: String,
	pub destination_port: u16,
	pub destination_port_description: &'a str,
	pub ip_version: &'a str,
	pub length: usize,
	pub checksum: u16,
	pub payload: &'a [u8],
	pub time: DateTime<Utc>
}

impl <'a> SimplePacket <'a> {
	pub fn new (
			category: &'a str,
			interface: String,
			source_address: String,
			source_port: u16,
			destination_address: String,
			destination_port: u16,
			ip_version: &'a str,
			length: usize,
			checksum: u16,
			payload: &'a [u8]
		) -> SimplePacket<'a> {

			// Get the descriptions for the destination and source ports from the
			// Port list
			let destination_port_description: &str = Port::find (destination_port).description;
			let source_port_description: &str = Port::find (source_port).description;

			// Get the current time to add it as the packet timestamp
			let time: DateTime<Utc> = Utc::now(); 

			SimplePacket {
				category,
				interface,
				source_address,
				source_port,
				source_port_description,
				destination_address,
				destination_port,
				destination_port_description,
				ip_version,
				length,
				checksum,
				payload,
				time
			}
	}
}

/// Implementing the Display trait allows us to format the way this struct is
/// printed out. When this trait is implemented, the to_string () method will
/// authomatically use it, similar to an overwrite of the toString () method on
/// other languages.
///
impl <'a> fmt::Display for SimplePacket <'a> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		write!(fmt, "{} Packet\nInterface: {}\nSource Address: {}\nSource Port: {} [{}]\nDestination Address: {}\nDestination Port: {} [{}]\nLength: {}\nChecksum: {}\nIP Version: {}\nReceived At: {:#?}",
            self.category.magenta ().bold (),
            self.interface.blue (),
            self.source_address,
            self.source_port,
            self.source_port_description.cyan (),
            self.destination_address,
           	self.destination_port,
           	self.destination_port_description.cyan (),
            self.length,
            self.checksum,
			self.ip_version,
			self.time
		)
	}
}