extern crate pnet;

mod port;
mod simple_packet;
mod simple_interface;
mod list;
mod sniffer;
mod connection;
mod action;

use pnet::datalink::{ self, NetworkInterface };

use std::env;
use std::io::{ self, Write };
use std::process;

use list::List;
use sniffer::*;
use simple_interface::*;
use action::Action;

fn main () {

    // Print the Process ID so it can later be tracked (Just to track performance)
    println! ("My pid is {}", process::id ());

    // Create a new List object where we'll hold all the IPs that are 
    // blacklisted.
    let mut blocklist: List = List::new ("Botnet Bad IPs", "List of Documented IPs related to botnet activity.");
    
    // Load each file we have into the block list
    blocklist.load ("assets/blocklists/botnets/zeus.txt", "Zeus Botnet");
    blocklist.load ("assets/blocklists/trojans/feodo.txt", "Feodo Tojan");
    blocklist.load ("assets/blocklists/others/tor.txt", "TOR Node");
    blocklist.load ("assets/blocklists/malware/bambenek.txt", "Cryptolocker - GameOver Zeus (p2p and post-Tovar) - tinba - matsnu - pushdo - qakbot");
    blocklist.load ("assets/blocklists/malware/irc.txt", "IRC Malware Distribution");

    // Create the whitelist of IPs allowed during non working hours
    let mut whitelist: List = List::new ("Non Working Hours Whitelist", "List of IPs devices are allowed to connect while not on working hours");

    // Load the whitelist items
    whitelist.load ("assets/whitelists/working_hours.txt", "Working Hour Whitelist");

    let mut keywords: List = List::new ("Keywords", "Keywords that will be looked into on the packets content");
    keywords.load("assets/keywords/command_control.txt", "Common commands that C&C traffic use");
    
    // Check if a network interface was given as a parameter when running the
    // tracker. If not, the program will end.
    let iface_name: String = match env::args ().nth (1) {
        Some (n) => n,
        None => {
            writeln! (io::stderr (), "USAGE: botnet-tracker <NETWORK INTERFACE> <ACTION_FLAG>").unwrap ();
            process::exit (1);
        }
    };

    let mut selected_action: Action = Action::NOTHING;

    // Get the action argument to know what action to take
    match env::args ().nth (2) {
        Some (a) => {
            if a == "-I" {
                println!("The Network Interface will be shut down if abnormal behavior is detected.");
                selected_action = Action::INTERFACE;
            } else if a == "-N" {
                println!("The Network will be changed if abnormal behavior is detected.");
                selected_action = Action::NETWORK;
            } else {
                println!("The Action argument provided was invalid, no action will be taken when detecting abnormal behaviors.");
                selected_action = Action::NOTHING;
            }
        },
        None => println!("No action argument was provided, no action will be taken when detecting abnormal behaviors.")
    };

    // Find the network interface with the provided name
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
   
    let interfaces = datalink::interfaces ();

    let network_interface: NetworkInterface = interfaces
        .into_iter ()
        .filter (interface_names_match)
        .next ()
        .unwrap ();

    if SimpleInterface::is_up (&network_interface) {
        let mut interface: SimpleInterface = SimpleInterface::new (network_interface);

        // Create a new sniffer with the specified interface and the created blocklist
        let mut sniffer = Sniffer::new (&mut interface, &blocklist, &whitelist, &keywords, selected_action);

        // Start analizing the traffic on the interface
        sniffer.start ();
    } else {
        println!("The interface is down.");
    }
}