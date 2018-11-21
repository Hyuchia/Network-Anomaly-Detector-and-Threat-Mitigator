extern crate chrono;
extern crate time;

use connection::chrono::prelude::*;
use connection::time::Duration;

/// Connection
/// 
/// A connection represents a simple connection to any IP address. It holds
/// information about the last time a connection with an IP happened and a weight
/// used to detect possible DDoS attacks.
/// 
pub struct Connection {
	pub last: DateTime<Utc>,
	pub current: DateTime<Utc>,
	pub weight: f32,
}

impl Connection {

	/// Create a new connection given the time of it.
	/// 
	/// # Arguments
	/// * `time: DateTime<Utc>` - The time where the connection ocurred
	/// 
	pub fn new (time: DateTime<Utc>) -> Connection {
		Connection {
			last: time,
			current: time,
			weight: 100f32
		}
	}

	/// Update a connection, setting the last connection time and the new weight
	/// for it. Lower weights will indicate there's a high amount of connections
	/// towards that address and if it reacheas a certain threshold, it could
	/// indicate a DDoS attack.
	/// 
	/// # Arguments
	/// `time: DateTime<Utc>` - The time stamp to update the connection with
	/// 
	/// # Output Data
	/// `weight: f32` - The current weight for the connection
	/// 
	pub fn update (&mut self, time: DateTime<Utc>) -> f32 {

		// Swap the time stamps
		self.last = self.current;
		self.current = time;

		// Get the duration between the last connection and the current one
		let duration = self.current.signed_duration_since (self.last);

		// Check if less than 1 second has passed (DDoS attacks usually send
		// thousands of requests in less than a second)
		if duration < Duration::milliseconds(500) {
			self.weight *= 0.9f32;
		} else {
			self.weight *= 20.2f32;
		}

		return self.weight;
	}
}