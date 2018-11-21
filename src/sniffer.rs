extern crate dns_lookup;
extern crate hash_ord;
extern crate colored;
extern crate chrono;
extern crate pnet;

// use sniffer::dns_lookup::{ lookup_host, lookup_addr };
use sniffer::hash_ord::hash_map::HashMap;
use sniffer::chrono::prelude::*;
use sniffer::colored::*;

use sniffer::pnet::datalink::{ self };
use sniffer::pnet::packet::arp::ArpPacket;
use sniffer::pnet::packet::ethernet::{ EtherTypes, EthernetPacket, MutableEthernetPacket };
use sniffer::pnet::packet::icmp::{ echo_reply, echo_request, IcmpPacket, IcmpTypes };
use sniffer::pnet::packet::icmpv6::Icmpv6Packet;
use sniffer::pnet::datalink::Channel::Ethernet;
use sniffer::pnet::packet::ip::{ IpNextHeaderProtocol, IpNextHeaderProtocols };
use sniffer::pnet::packet::ipv4::Ipv4Packet;
use sniffer::pnet::packet::ipv6::Ipv6Packet;
use sniffer::pnet::packet::tcp::TcpPacket;
use sniffer::pnet::packet::udp::UdpPacket;
use sniffer::pnet::packet::Packet;
use sniffer::pnet::util::MacAddr;

use list::*;
use simple_packet::*;
use simple_interface::*;

use std::net::IpAddr;

use action::*;

use connection::*;

/// Sniffer
/// 
/// The Sniffer is the main struct used on this program. It implements all the
/// logic required to get the traffic from a network interface, retrieve the packets
/// and their information for each network layer. The functionality presented here
/// is based on the Basic functionality provided by the pnet library.
/// 
pub struct Sniffer <'a> {
	pub interface: &'a mut SimpleInterface,
	pub blocklist: &'a List<'a>,
	pub whitelist: &'a List<'a>,
	pub keywords: &'a List<'a>,
	pub connections: HashMap <String, Connection>,
	pub action: Action,
	pub counter: HashMap <String, [i32; 2]>
}

impl <'a> Sniffer <'a> {

	/// Create a new Sniffer instance.
	/// 
	/// # Arguments
	/// * `interface: &'a NetworkInterface` - The interface from where to get the traffic
	/// * `blocklist: &'a List` - An instance of a List with all the IPs to be blacklisted
	/// * `whitelist: &'a List` - An instance of a List with all the IPs to be whitelisted 
	///                           when connected outside of working hours
	/// * `keywords: &'a List` - An instance of a List with all the Keywords to look for
	///                          on the packets payload
	/// * `action: Action` - The action to execute when anomalous activity is detected
	/// 
	/// # Output Data
	/// * `sniffer: Sniffer<'a>` - New instance of a Sniffer
	/// 
	pub fn new (interface: &'a mut SimpleInterface, blocklist: &'a List, whitelist: &'a List, keywords: &'a List, action: Action) -> Sniffer <'a> {

		// Get the name of the interface

		println! ("------------------------------------------------------------");
		println! ("{}", interface);
		println! ("------------------------------------------------------------");

		// Create the connections hashmap
		let connections: HashMap<String, Connection> = HashMap::new ();

		// Create the counter hashmap and fill initial values
		let mut counter: HashMap <String, [i32; 2]> = HashMap::new ();
		counter.insert ("TCP".to_string (), [0, 0]);
		counter.insert ("UDP".to_string (), [0, 0]);
		counter.insert ("ICMP".to_string (), [0, 0]);
		counter.insert ("ARP".to_string (), [0, 0]);

		// Create the sniffer object
		Sniffer {
			interface,
			blocklist,
			whitelist,
			keywords,
			connections,
			action,
			counter
		}
	}

	/// Update the counter of Incoming and Outgoing packets for a specified protocol
	/// 
	/// # Arguments
	/// * `packet_type: String` - The Protocol of the packet (TCP|UDP|ICMP|ARP)
	/// * `source: bool` - Whether the packet's source is this device or not
	/// * `destination: bool` - Whether the packet's destination is this device or not
	/// 
	pub fn update_counter (&mut self, packet_type: String, source: bool, destination: bool) {
			
		// Get the current value for the counter
		let mut counter_value: [i32; 2] = *self.counter.get_mut (&packet_type).unwrap ();
		
		// Modify the correct index depending on if the packet is Incoming/Outgoing
		if source {
			counter_value[1] += 1;
		} else if destination {
			counter_value[0] += 1;
		}

		// Update the counter with the latest values
		self.counter.insert (packet_type.to_string (), counter_value);

		println! ("------------------------------------------------------------");
		println!("{} Packets - {} Incoming {} Outgoing", packet_type, counter_value[0], counter_value[1]);
	}

	/// Perform all the checks available on a given packet. This will perform the
	/// check for DDoS attacks, Working Hour interval connections, Payload Keywords
	/// and BlockList addresses.
	/// 
	/// # Arguments
	/// * `packet: SimplePacket` - The packet to analyse
	/// 
	pub fn perform_check (&mut self, packet: SimplePacket) {

		// Check if the packet source is this device
		let source: bool = self.interface.ipv4.contains (&packet.source_address) || self.interface.ipv6.contains (&packet.source_address);

		// Check if the packet destination is this device
		let destination: bool = self.interface.ipv4.contains (&packet.destination_address) || self.interface.ipv6.contains (&packet.destination_address);

		// Check if the packet source or destination address belongs to this device
		let self_request: bool = source || destination; 

		let request_type: String = packet.category.to_string ();

		// Perform all checks to determine bad behaviors
		let blocklist: bool = self.blocklist_check (&packet);
		let working_hours: bool = self.working_hours_check (&packet);
		let keyword: bool = self.keyword_check (&packet);
		let ddos: bool = self.ddos_check (packet);

		if self_request {
			// Update the counter
			self.update_counter (request_type, source, destination);

			// If the request came from this computer or to this computer, 
			// shut down the interface to prevent further damage.
			if blocklist || working_hours || ddos || keyword {
				if self.action == Action::INTERFACE {
					self.interface.down ();
				} else if self.action == Action::NETWORK {
					self.interface.setup ("192.168.0.110", "255.255.255.0", "192.168.0.1");
				}
			}
		}
	}

	pub fn handle_udp_packet(&mut self, source: IpAddr, destination: IpAddr, packet: &[u8]) {
		let udp = UdpPacket::new(packet);

		// Check if the packet is valid. If not, print it as malformed
		if let Some(udp) = udp {

			// let source_host = lookup_addr(&destination).unwrap();
  			// let destination_host = lookup_addr(&destination).unwrap();

			// let source_host = "Unknown";
  			// let destination_host = "Unknown";

			// Add to the UDP counter
			
			let received_packet = SimplePacket::new (
				"UDP",
				self.interface.name.to_string(),
				source.to_string(),
				udp.get_source(),
				destination.to_string(),
				udp.get_destination(),
				match source {
					IpAddr::V4(..) => "IPv4",
					_ => "IPv6",
				},
				packet.len(),
				udp.get_checksum (),
				udp.payload ()
			);
			
			println!("{}", received_packet);
			self.perform_check (received_packet);
			println! ("------------------------------------------------------------");
		} else {
			println!("[{}]: Malformed UDP Packet", self.interface.name);
		}
	}

	/// Handle ICMP packets.
	pub fn handle_icmp_packet(&mut self, source: IpAddr, destination: IpAddr, packet: &[u8]) {
		let icmp_packet = IcmpPacket::new(packet);

		// Check if the packet source is this device
		let is_source: bool = self.interface.ipv4.contains (&source.to_string ());

		// Check if the packet destination is this device
		let is_destination: bool = self.interface.ipv4.contains (&destination.to_string ());

		if let Some(icmp_packet) = icmp_packet {

			match icmp_packet.get_icmp_type() {
				IcmpTypes::EchoReply => {
					let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
					println!(
						"{}\nInterface: {}\nSource: {}\nDestination: {}\n(seq={:?}, id={:?})",
						"ICMP Echo Reply".yellow ().bold (),
						self.interface.name.blue (),
						source,
						destination,
						echo_reply_packet.get_sequence_number(),
						echo_reply_packet.get_identifier()
					);
					self.update_counter("ICMP".to_string (), is_source, is_destination);
				}
				IcmpTypes::EchoRequest => {
					let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
					println!(
						"{}\nInterface: {}\nSource: {}\nDestination: {}\n(seq={:?}, id={:?})",
						"ICMP Echo Request".yellow ().bold (),
						self.interface.name.blue (),
						source,
						destination,
						echo_request_packet.get_sequence_number(),
						echo_request_packet.get_identifier()
					);
					self.update_counter("ICMP".to_string (), is_source, is_destination);
				}
				_ => {
					println!(
						"{}\nInterface: {}\nSource: {}\nDestination: {}\n(type={:?})",
						"ICMP Packet".yellow ().bold (),
						self.interface.name,
						source,
						destination,
						icmp_packet.get_icmp_type()
					);
					self.update_counter("ICMP".to_string (), is_source, is_destination);
				},
			}
			println! ("------------------------------------------------------------");
		} else {
			println!("[{}]: Malformed ICMP Packet", self.interface.name);
		}
	}

	pub fn handle_icmpv6_packet(&mut self, source: IpAddr, destination: IpAddr, packet: &[u8]) {
		let icmpv6_packet = Icmpv6Packet::new(packet);
		if let Some(icmpv6_packet) = icmpv6_packet {
			// Check if the packet source is this device
			let is_source: bool = self.interface.ipv6.contains (&source.to_string ());

			// Check if the packet destination is this device
			let is_destination: bool = self.interface.ipv6.contains (&destination.to_string ());
			println!(
				"[{}]: ICMPv6 packet {} -> {} (type={:?})",
				self.interface.name,
				source,
				destination,
				icmpv6_packet.get_icmpv6_type()
			);
			self.update_counter("ICMP".to_string (), is_source, is_destination);
			println! ("------------------------------------------------------------");
		} else {
			println!("[{}]: Malformed ICMPv6 Packet", self.interface.name);
		}
	}

	/// Handle a TCP Packet.
	pub fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, packet: &[u8]) {
		let tcp = TcpPacket::new(packet);

		// Check if the packet is valid. If not, print it as malformed
		if let Some(tcp) = tcp {
			
			// let source_host = lookup_addr(&destination).unwrap();
  			// let destination_host = lookup_addr(&destination).unwrap();

			// let source_host = "Unknown";
  			// let destination_host = "Unknown";

			let received_packet = SimplePacket::new (
				"TCP",
				self.interface.name.to_string(),
				source.to_string(),
				tcp.get_source(),
				destination.to_string(),
				tcp.get_destination(),
				match source {
					IpAddr::V4(..) => "IPv4",
					_ => "IPv6",
				},
				packet.len(),
				tcp.get_checksum (),
				tcp.payload ()
			);

			println!("{}", received_packet);
			self.perform_check (received_packet);
			println! ("------------------------------------------------------------");
		} else {
			println!("[{}]: Malformed TCP Packet", self.interface.name);
		}
	}

	/// Handle transport layer packets. From here, each packet will be handled
	/// differently depending on the protocol it's using (TCP, UDP, ICMP)
	pub fn handle_transport_protocol(
		&mut self, 
		source: IpAddr,
		destination: IpAddr,
		protocol: IpNextHeaderProtocol,
		packet: &[u8],
	) {
		match protocol {
			IpNextHeaderProtocols::Udp => {
				self.handle_udp_packet(source, destination, packet)
			}
			IpNextHeaderProtocols::Tcp => {
				self.handle_tcp_packet(source, destination, packet)
			}
			IpNextHeaderProtocols::Icmp => {
				self.handle_icmp_packet(source, destination, packet)
			}
			IpNextHeaderProtocols::Icmpv6 => {
				self.handle_icmpv6_packet(source, destination, packet)
			}
			_ => println!(
				"[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
				self.interface.name,
				match source {
					IpAddr::V4(..) => "IPv4",
					_ => "IPv6",
				},
				source,
				destination,
				protocol,
				packet.len()
			),
		}
	}

	/// Handle an IPv4 packet. From here we'll send it to another handler that
	/// will deal with the Transport protocols (Layer 4)
	pub fn handle_ipv4_packet(&mut self, ethernet: &EthernetPacket) {
		let header = Ipv4Packet::new(ethernet.payload());

		// Check if the header is valid. If not, print it as a malformed packet
		if let Some(header) = header {
			// Send the packet's information to the transport handler
			self.handle_transport_protocol(
				IpAddr::V4(header.get_source()),
				IpAddr::V4(header.get_destination()),
				header.get_next_level_protocol(),
				header.payload(),
			);
		} else {
			println!("[{}]: Malformed IPv4 Packet", self.interface.name);
		}
	}

	/// Handle an IPv6 packet. From here we'll send it to another handler that
	/// will deal with the Transport protocols (Layer 4)
	pub fn handle_ipv6_packet(&mut self, ethernet: &EthernetPacket) {
		let header = Ipv6Packet::new(ethernet.payload());

		// Check if the header is valid. If not, print it as a malformed packet
		if let Some(header) = header {
			// Send the packet's information to the transport handler
			self.handle_transport_protocol(
				IpAddr::V6(header.get_source()),
				IpAddr::V6(header.get_destination()),
				header.get_next_header(),
				header.payload(),
			);
		} else {
			println!("[{}]: Malformed IPv6 Packet", self.interface.name);
		}
	}

	/// Handle an ARP packet. Right now, only it's information is being printed:
	/// 
	/// # Output Data
	/// 
	/// * ARP Packet
	/// * Interface
	/// * Sender MAC Address
	/// * Sender IP Address
	/// * Target MAC Address
	/// * Target IP Address
	/// * Operation
	pub fn handle_arp_packet(&mut self, ethernet: &EthernetPacket) {
		let header = ArpPacket::new(ethernet.payload());
		if let Some(header) = header {

			// Check if the packet source is this device
			let source: bool = self.interface.ipv4.contains (&header.get_sender_proto_addr().to_string ()) || self.interface.ipv6.contains (&header.get_sender_proto_addr().to_string ());

			// Check if the packet destination is this device
			let destination: bool = self.interface.ipv4.contains (&header.get_target_proto_addr().to_string ()) || self.interface.ipv6.contains (&header.get_target_proto_addr().to_string ());
			
			println!(
				"{}\nInterface: {}\nSender MAC Address: {}\nSender IP Address: {}\nTarget MAC Address: {}\nTarget IP Address: {}\nOperation: {:?}",
				"ARP Packet".red ().bold (),
				self.interface.name.blue (),
				ethernet.get_source(),
				header.get_sender_proto_addr(),
				ethernet.get_destination(),
				header.get_target_proto_addr(),
				header.get_operation()
			);
			self.update_counter("ARP".to_string (), source, destination);
			println! ("------------------------------------------------------------");
		} else {
			println!("[{}]: Malformed ARP Packet", self.interface.name);
		}
	}

	/// Receive an Ethernet Frame (Layer 2) and check to what method we should
	/// send it to according to the Nework Protocol (Layer 3) it's using.
	pub fn handle_ethernet_frame(&mut self, ethernet: &EthernetPacket) {

		// Check what kind of packet it is or print it as unknown
		match ethernet.get_ethertype() {
			// Handle IPv4 packets
			EtherTypes::Ipv4 => self.handle_ipv4_packet(ethernet),

			// Handle IPv6 packets
			EtherTypes::Ipv6 => self.handle_ipv6_packet(ethernet),

			// Handle ARP packets
			EtherTypes::Arp => self.handle_arp_packet(ethernet),

			// If none of above, just print it as unknown
			_ => println!(
				"[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
				self.interface.name,
				ethernet.get_source(),
				ethernet.get_destination(),
				ethernet.get_ethertype(),
				ethernet.packet().len()
			),
		}
	}

	/// Start receiving all packets available on the interface so that they can
	/// be analized.
	/// 
	pub fn start (&mut self) {
		
		// Create a Data Link channel to receive on
		let (_, mut rx) = match datalink::channel(&self.interface.interface, Default::default()) {
			Ok (Ethernet (tx, rx)) => (tx, rx),
			Ok (_) => panic!("packetdump: unhandled channel type: {}"),
			Err (e) => panic!("packetdump: unable to create channel: {}", e),
		};

		loop {
			// Check if the interface is UP
			if SimpleInterface::is_up (&self.interface.interface) {
				// Create a buffer where the packet contents will be saved
				let mut buf: [u8; 2000] = [0u8; 2000];

				// Create a dummy ethernet frame
				let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

				// Receive the next packet available
				match rx.next () {

					// Check if what we received was actually a Packet
					Ok(packet) => {
						if cfg!(target_os = "macos") && self.interface.interface.is_up() && !self.interface.interface.is_broadcast()
							&& !self.interface.interface.is_loopback() && self.interface.interface.is_point_to_point()
						{
							// Maybe is TUN interface
							let version = Ipv4Packet::new(&packet).unwrap().get_version();

							// Check what IP version the packet is using
							if version == 4 {
								// Fill additional data in the dummy frame
								fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
								fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
								fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);

								// Add the payload of the packet to the frame
								fake_ethernet_frame.set_payload(&packet);
								self.handle_ethernet_frame(&fake_ethernet_frame.to_immutable());
								continue;
							} else if version == 6 {
								// Fill additional data in the dummy frame
								fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
								fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
								fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);

								// Add the payload of the packet to the frame
								fake_ethernet_frame.set_payload(&packet);
								self.handle_ethernet_frame(&fake_ethernet_frame.to_immutable());
								continue;
							}
						}
						self.handle_ethernet_frame(&EthernetPacket::new(packet).unwrap());
					}
					Err (e) => {
						if self.interface.interface.is_up () {
							println!("Unable to receive packet: {}", e);
							
						} else {
							println!("The Interface {} is down.", self.interface.name);
						}
					}
				}
			} else {
				println!("The Interface {} is down.", self.interface.name);
				//break;
			}
		}
	}
}

/// This Implementation Block has been separated just to provide a separation
/// between the Sniffer functionality and the Rules it enforces.
impl <'a> Sniffer <'a> {

	/// Check if there is a possible DDoS attack going on based on the weight
	/// of the Connection registered to an IP address.
	/// 
	/// # Arguments
	/// * `packet: SimplePacket` - The packet to analyse
	/// 
	/// # Output Data
	/// * `bool` - Wether or not the weight of a connection is low enough to be
	/// 		   considered an attack.
	/// 
	pub fn ddos_check (&mut self, packet: SimplePacket) -> bool {

		// Don't perform any check if the address corresponds to a multicast address
		// since those will be very common and would always trigger a DDoS alert
		if packet.destination_address != "ff02::fb" && packet.destination_address != "ff01::fb" && packet.destination_address != "ff05::fb" {

			// Check if there was already a Connection item for that address.
			// If there was none, a new one will be created
			if self.connections.contains_key (&packet.destination_address) {

				let found = self.connections.get_mut (&packet.destination_address).unwrap ();

				// Update the Connection with a new time stamp
				let weigth: f32 = found.update (packet.time);

				// If the weight of the connection has reached a number below 1
				// we can consider it already had too many connections and it may
				// be a DDoS attack
				if weigth < 1f32 {
					println!("{}", format!("Possible Attempt of DDoS Attack to IP: {} - Weight: {}", &packet.destination_address, weigth).red ().bold ());
				}
				return true;
			} else {
				self.connections.insert (packet.destination_address, Connection::new (packet.time));
			}
		}
		
		return false;
	}

	/// Checks if the time of a packet is between the defined working hours interval
	/// and if it is not, it checks if its addresses were whitelisted for this
	/// behavior or not.
	/// 
	/// # Arguments
	/// * `packet: &'a SimplePacket` - The packet to analyse
	/// 
	/// # Output Data
	/// * `bool` - Whether the reception of this packet is anomalous or not
	/// 
	pub fn working_hours_check (&self, packet: &'a SimplePacket) -> bool {
		// Retrieve the hour part of the packet's time
		let hour = packet.time.hour ();

		// Check if the hour is outside of the working time period.
		if  hour < 7 || hour > 22 {

			// Check if the source address or destination address were whitelisted
			// if not, show a warning.
			if !(self.whitelist.contains(&packet.source_address) || self.whitelist.contains(&packet.destination_address)) {
				println!("{}", "Connection to Non Authorized IP During Non Working Hours".red ().bold ());
				return true;
			}
		}

		return false;
	}

	/// Checks if the source or destination IP addresses on a packet are present
	/// on any of the lists loaded on the blocklist. 
	/// 
	/// # Arguments
	/// * `packet: &'a SimplePacket` - The packet to analyse
	/// 
	/// # Output Data
	/// * `bool` - Whether or not the addresses were present on the blocklist
	/// 
	pub fn blocklist_check (&self, packet: &'a SimplePacket) -> bool {
		let none: String = String::from ("None");

		let mut warning: &String = &none;

		// Check if the source address is listed on the block list
		if self.blocklist.contains (&packet.source_address) {
			warning = self.blocklist.get (&packet.source_address).unwrap ();
		}

		// Check if the destination address is listed on the block list
		if self.blocklist.contains (&packet.destination_address) {
			warning = self.blocklist.get (&packet.destination_address).unwrap ();
		}

		// If a warning was found, then print it.
		if warning != &none {
			println!("{} ({})", "Connection to Black Listed IP Address Detected".red ().bold (), warning.red ().bold ());
			return true;
		}
		
		return false;
	}

	/// Check if the payload of a packet contains one of the keywords inside the
	/// keyword list.
	/// 
	/// # Arguments
	/// * `packet: &'a SimplePacket` - The packet to analyse
	/// 
	/// # Output Data
	/// * `bool` - Whether a keyword was found on the payload or not.
	/// 
	pub fn keyword_check (&self, packet: &'a SimplePacket) -> bool {
		// Transform the packet payload (An array of bytes) into a String. Because
		// of things as SSL and other elements, this String might not provide an
		// understandable String but instead raw data.
		let payload: String = String::from_utf8_lossy (packet.payload).to_string ().to_lowercase ();

		// Iterate over all the available keywords and check if they can be found
		// anywhere on the payload
		for keyword in self.keywords.map.keys () {
			if payload.contains (keyword) {
				let warning = self.keywords.get (keyword).unwrap ();
				println!("{} ({} - {})", "Keyword detected on Packet Payload".red ().bold (), keyword.red (). bold (), warning.red ().bold ());
				return true;
			}	
		}

		return false;
	}
}
