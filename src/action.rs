/// Action
/// 
/// This enumeration defines all the possible actions the program might
/// perform if any anomalous activity is detected on the network. The action
/// is defined by the user by specifying an Action Flag (-I or -N) when running
/// the program. Since the program must be run with administration permissions, 
/// no further permissions are needed to execute these commands
#[derive(PartialEq, Eq)]
pub enum Action {
	INTERFACE,
    NETWORK,
	NOTHING
}
