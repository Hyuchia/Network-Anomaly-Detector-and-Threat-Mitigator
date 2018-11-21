extern crate pnet;

use simple_interface::pnet::datalink::NetworkInterface;

use std::process::Command;
use std::fmt;

/// Simple Interface
/// 
/// This struct holds the basic information of a network interface, including
/// its name, ipv4, ipv6 and mac. It also holds the actual interface object.
/// 
pub struct SimpleInterface {
	pub interface: NetworkInterface,
	pub name: String,
	pub ipv4: String,
	pub ipv6: String,
	pub mac: String
}

impl SimpleInterface {
	
	/// Create a new Simple Interface instance.
	/// 
	/// # Arguments
	/// * `interface: &'a NetworkInterface` - The interface this struct is representing
	/// 
	/// # Output Data
	/// * `interface: SimpleInterface <'a>` - The created instance
	/// 
	pub fn new (interface: NetworkInterface) -> SimpleInterface {
		
		if SimpleInterface::is_up(&interface) {
			let name: String = interface.name[..].to_string ();

			let ipv4: String = interface.ips[0].to_string ();

			let ipv6: String = interface.ips[1].to_string ();

			let mac: String = interface.mac_address ().to_string ();

			SimpleInterface {
				interface,
				name,
				ipv4,
				ipv6,
				mac
			}
		} else {
			panic! ("The interface is down");
		}
		
	}

	/// Shut down a network interface. Depending on the target operating system
	/// a command will be issued to shut down the given interface.
	/// The goal of this action is to shut down any connections and prevent the 
	/// possible spreading of the malware and cripple the actions a bot could 
	/// perform. 
	/// 
	pub fn down (&self) {
		// First detect the OS in order to determine what commands an tools should
		// be used
		if cfg!(target_os = "windows") {
			Command::new ("cmd")
				.args (&["/C", &format!("netsh interface set interface \"{}\" admin=disable", self.name)])
				.output ()
				.expect ("Failed to execute process");
		} else if cfg!(target_os = "macos") {
			Command::new ("sh")
				.arg ("-c")
				.arg (format!("sudo ifconfig {} down", self.name))
				.output ()
				.expect ("Failed to execute process");
		} else {
			Command::new ("sh")
				.arg ("-c")
				.arg (format!("sudo ip link set dev {} down", self.name))
				.output ()
				.expect ("Failed to execute process");
		}
	}

	/// Turn on a network interface. Depending on the target operating system
	/// a command will be issued to turn on the given interface.
	/// 
	pub fn up (&self) {
		// First detect the OS in order to determine what commands an tools should
		// be used
		if cfg!(target_os = "windows") {
			Command::new ("cmd")
				.args (&["/C", &format!("netsh interface set interface \"{}\" admin=enable", self.name)])
				.output ()
				.expect ("Failed to execute process");
		} else if cfg!(target_os = "macos") {
			Command::new ("sh")
				.arg ("-c")
				.arg (format!("sudo ifconfig {} up", self.name))
				.output ()
				.expect ("Failed to execute process");
		} else {
			Command::new ("sh")
				.arg ("-c")
				.arg (format!("sudo ip link set dev {} up", self.name))
				.output ()
				.expect ("Failed to execute process");
		}
	}

	/// Change the network settings of an interface. This will change the IP, 
	/// subnet mask and default gateway settings for interface. 
	/// The goal of this action is to change the device to another network, ideally
	/// one build out of honeypots so the malware can be analysed and contained.
	/// 
	/// # Arguments
	/// `ip: &str` - The new IP to assign
	/// `netmask: &str` - The new subnetmask to assign
	/// `gateway: &str` - The new default gateway IP to assign
	/// 
	pub fn setup (&mut self, ip: &str, netmask: &str, gateway: &str) {
		if self.ipv4 != ip {
			println!("Setting up Interface {} -> {}", self.ipv4, ip);
			// First detect the OS in order to determine what commands an tools should
			// be used
			if cfg!(target_os = "windows") {
				Command::new ("cmd")
					.args (&["/C", &format!("netsh interface ipv4 set address name=\"{}\" static {} {} {}", self.name, ip, netmask, gateway)])
					.output ()
					.expect ("Failed to execute process");
			} else if cfg!(target_os = "macos") {
				Command::new ("sh")
					.arg ("-c")
					.arg (format!("sudo networksetup -setmanual \"{}\" {} {} {}", self.name, ip, netmask, gateway))
					.output ()
					.expect ("Failed to execute process");
			} else {
				Command::new ("sh")
					.arg ("-c")
					.arg (format!("sudo ifconfig {} {} netmask {}", self.name, ip, netmask))
					.output ()
					.expect ("Failed to execute process");
				Command::new ("sh")
					.arg ("-c")
					.arg (format!("sudo route add default gw {} {}", gateway, self.name))
					.output ()
					.expect ("Failed to execute process");
			}
		}
		self.ipv4 = ip.to_string ();
	}

	/// Check if an interface is active.
	/// 
	/// # Arguments
	/// * `interface: &'a NetworkInterface` - The network interface to check
	/// 
	/// # Output Data
	/// * `bool` - Whether or not the interface is active or not
	/// 
	pub fn is_up <'a> (interface: &'a NetworkInterface) -> bool {
		return interface.is_up () && interface.ips.len () > 1;
	}
}

/// Implementing the Display trait allows us to format the way this struct is
/// printed out. When this trait is implemented, the to_string () method will
/// authomatically use it, similar to an overwrite of the toString () method on
/// other languages.
///
impl fmt::Display for SimpleInterface {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		write!(fmt, "Interface Information\nName: {}\nIPv4: {}\nIPv6: {}\nMAC: {}",
           self.name,
		   self.ipv4,
		   self.ipv6,
		   self.mac
		)
	}
}