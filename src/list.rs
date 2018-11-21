
extern crate hash_ord;

use list::hash_ord::hash_map::HashMap;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::path::Path;

pub struct List <'a> {
	pub name: &'a str,
	pub description: &'a str,
	pub map: HashMap <String, String>
}

impl <'a> List <'a> {

	/// Create a new ist given some initial data. This is an equivalent to a 
	/// constructor on Object-Oriented languages.
	/// 
	/// # Arguments
	/// * `name` - The name of the List
	/// * `description` - A simple description of the list
	/// 
	/// # Output Data
	/// * `list: List` - A new List instance
	/// 
	pub fn new (name: &'a str, description: &'a str) -> List <'a> {
		let map: HashMap<String, String> = HashMap::new ();
		List {
			name,
			description,
			map
		}
	}

	/// Load a file's information into the list.
	/// 
	/// # Arguments
	/// * `file_name: &str` - The path to the file to load
	/// * `info: &str` - The information of the file. This will be shown as the warning
	/// 	if some device were to connect to an IP belonging to the file
	/// 
	pub fn load (&mut self, file_name: &str, info: &str) {
		let path: &Path = Path::new (file_name);

		// Try to open the file, if the file can't be opened the program will panic
		let file = match File::open (&path) {
			Ok (file) => file,
			Err (e) => {
				// fallback in case of failure.
				// you could log the error, panic, or do anything else.
				panic! ("{}", e);
			}
		};

		// Read all contents into a buffer reader
		let file = BufReader::new (&file);

		// Line by line, add every IP into the list
		for line in file.lines () {

			// Get the current line value
			let l = line.unwrap ();

			// Trim the line
			let lt = l.trim ();

			// Check if it's not a comment or is empty
			if !(lt.starts_with ("#") || lt.is_empty ()) {
				self.add (lt.to_string (), info.to_string ());
			}
		}
	}

	/// Check if the list contains a given IP
	/// 
	/// # Arguments
	/// * `key: &String` - The key to look out for
	/// 
	/// # Output Data
	/// * `bool` - Wether or not this list contains the provided key
	/// 
	pub fn contains (&self, key: &String) -> bool {
		return self.map.contains_key (key);
	}

	/// Get the description for a given IP. This description will be the `info`
	/// parameter with which the block list was loaded
	/// 
	/// # Arguments
	/// * `key: &String` - The key of the element to get the value for
	/// 
	/// # Output
	/// * `value: Option <&String>` - An optional holding the value of the provided key
	/// 
	pub fn get (&self, key: &String) -> Option <&String> {
		return self.map.get (key);
	}

	/// Add a new IP to the list
	/// 
	/// # Arguments
	/// * `key: String` - The key of the value to add
	/// * `value: String` - The value to add
	/// 
	pub fn add (&mut self, key: String, value: String) {
		self.map.insert (key, value);
	}
}