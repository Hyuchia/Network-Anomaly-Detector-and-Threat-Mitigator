/// Port
/// 
/// This struct holds the known information of a port, such as its number, 
/// description, protocol and status. This is mainly used to fill out the description
/// field on the Simple Packets of the Sniffer.
/// 
pub struct Port <'a> {
	pub port: u16,
	pub description: &'a str,
	pub protocol: &'a str,
	pub status: &'a str
}

impl <'a> Port <'a> {

	/// Create a new Port given some initial data. This is an equivalent to a 
	/// constructor on Object-Oriented languages
	pub fn new (port: u16, description: &'a str, protocol: &'a str, status: &'a str) -> Port <'a> {
		Port {
			port,
			description,
			protocol,
			status
		}
	}

	/// Find a Port by it's port number. This method will iterate over the list
	/// below to try to find a port matching the port number given. If no match
	/// is found, the UNKNOWN place holder port is returned.
	/// 
	/// # Arguments
	/// * `port: u16` The port number to look for
	/// 
	/// # Output Data
	/// * `port: &'a Port<'a>` - The Port struct that matches the given port number
	///  
	pub fn find (port: u16) -> &'a Port<'a> {
		for item in LIST.iter () {
            if item.port == port {
                return item;
            }
        }
		return UNKNOWN;
	}
}

/// This port is used as a place holder when a port is not registered in the 
/// list available below.
pub const UNKNOWN: &Port = &Port {
	port: 0,
	description: "Unknown",
	status: "Unofficial",
	protocol: "Unknown"
};

/// Simple list of the commonly used and known Ports
pub const LIST: [Port; 57] = [
	Port {
		port: 0,
		description: "Reserved",
		protocol: "UDP",
		status: "Official"
	},
	Port {
		port: 7,
		description: "Echo Protocol",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 20,
		description: "FTP data transfer",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 21,
		description: "FTP control (command)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 22,
		description: "Secure Shell (SSH) — used for secure logins, file transfers (scp, sftp) and port forwarding",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 23,
		description: "Telnet protocol—unencrypted text communications",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 25,
		description: "Simple Mail Transfer Protocol (SMTP)—used for e-mail routing between mail servers",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 42,
		description: "Windows Internet Name Service/ARPA Host Name Server Protocol",
		protocol: "TCP/UDP",
		status: "Unofficial/Official"
	},
	Port {
		port: 43,
		description: "WHOIS protocol",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		description: "Domain Name System (DNS)",
		port: 53,
		status: "Official",
		protocol: "TCP/UDP"
	},
	Port {
		port:80,
		description: "Hypertext Transfer Protocol (HTTP)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 109,
		description: "Post Office Protocol v2 (POP2)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 110,
		description: "Post Office Protocol v3 (POP3)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 115,
		description: "Simple File Transfer Protocol (SFTP)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 118,
		description: "SQL (Structured Query Language) Services",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 137,
		description: "NetBIOS NetBIOS Name Service",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 139,
		description: "NetBIOS NetBIOS Session Service",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 143,
		description: "Internet Message Access Protocol (IMAP)—management of email messages",
		protocol: "TCP",
		status: "Official"
		
	},
	Port {
		port: 194,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 220,
		description: "Internet Message Access Protocol (IMAP), version 3",
		protocol: "TCP/UDP",
		status: "Official"
	},
	
	Port {
		port: 443,
		description: "Hypertext Transfer Protocol over TLS/SSL (HTTPS)",
		status: "Official",
		protocol: "TCP"
	},
	Port {
		port: 445,
		description: "Microsoft-DS SMB file sharing",
		status: "Official",
		protocol: "TCP"
	},
	Port {  
		port: 520,
		description: "Routing Information Protocol (RIP)",
		protocol: "UDP",
		status: "Official"   
    },
	Port {
		port: 546,
		description: "DHCPv6 client",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 547,
		description: "DHCPv6 server",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 548,
		description: "Apple Filing Protocol (AFP) over TCP",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 989,
		description: "FTPS Protocol (data): FTP over TLS/SSL",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 990,
		description: "FTPS Protocol (control): FTP over TLS/SSL",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 992,
		description: "TELNET protocol over TLS/SSL",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 993,
		description: "Internet Message Access Protocol over TLS/SSL (IMAPS)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 995,
		description: "Post Office Protocol 3 over TLS/SSL (POP3S)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 1194,
		description: "OpenVPN",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 1433,
		description: "MSSQL (Microsoft SQL Server database management system) Server",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 1434,
		description: "MSSQL (Microsoft SQL Server database management system) Monitor",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 1512,
		description: "Microsoft Windows Internet Name Service (WINS)",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 1725,
		description: "Valve Steam Client",
		protocol: "UDP",
		status: "Unofficial"
	},
	Port {     
		port: 2083,
		description: "CPanel default SSL",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 3306,
		description: "MySQL database system",
		protocol: "TCP/UDP",
		status: "Official"
    },
	Port {
		port: 5228,
		description: "Google Play, Android Cloud to Device Messaging Service, Google Cloud Messaging",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 5353,
		description: "Multicast DNS (mDNS)",
		protocol: "UDP",
		status: "Official"
	},
	Port {
		port: 5900,
		description: "Virtual Network Computing (VNC) remote desktop protocol",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 5984,
		description: "CouchDB database server",
		protocol: "TCP/UDP",
		status: "Official"
	},
	Port {
		port: 6660,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6661,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6662,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6663,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6664,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6665,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6666,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6667,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Official"
	},
	Port {
		port: 6668,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6669,
		description: "Internet Relay Chat (IRC)",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6679,
		description: "IRC SSL (Secure Internet Relay Chat)—often used",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 6697,
		description: "IRC SSL (Secure Internet Relay Chat)—often used",
		protocol: "TCP",
		status: "Unofficial"
	},
	Port {
		port: 25565,
		description: "MySQL Standard MySQL port",
		protocol: "TCP/UDP",
		status: "Unofficial"
	},
	Port {
		port: 27017,
		description: "mongoDB server port",
		protocol: "TCP/UDP",
		status: "Unofficial"
	},
	Port {
		port: 33434,
		description: "traceroute",
		protocol: "TCP/UDP",
		status: "Official"
	}
];