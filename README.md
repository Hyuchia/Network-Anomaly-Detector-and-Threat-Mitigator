# Network Anomaly Detector and Threat Mitigator (N.A.D.T.M)

This project is meant to be used as a way to detect botnet activity inside a network, however, since the checks it 
performs are pretty general, it could be used to detect any kind of malware activity.

The ideal device to run this in is on a Raspberry Pi that can monitor your network without the possibility of getting
compromised, however, it can be run on any device with **Windows, macOS or Linux**.

This project will detect anomalous behavior on the network, such as:

* Attempts of DDoS attacks (incoming and outgoing)
* Connections to non-whitelisted IP addresses outside of working ours (defined 7 am to 10 pm)
* Connections to blocklisted IP addresses
* Detection of defined keywords on any packets' payload

When one of the previous behaviors is detected, there are 3 actions that can be executed:

* Shut Down Interface (`-I`): This will shut down the network interface in order to prevent the spreading of malware or bot replication as well as any malicious activity
* Change Network Settings (`-N`): This will change the device to another network (The other network should be dedicated to malware analysis and ideally made out of honeypots)
* Nothing: No action will be taken

## The Team

This project was created by:

* Alejandra Cuéllar Gonzalez <A01333324@itesm.mx>
* Cinthya Daniela Lugo Novoa <A01332942@itesm.mx>
* Diego Islas Ocampo <A01332956@itesm.mx>
* Irvin Uriel Mundo Rivera <A01333820@itesm.mx>
* Luis Fernando Saavedra Meza <A01333410@itesm.mx>

## License

This project and all its contents are released under the [GPLv3 License](./LICENSE.md)

## Assets

This project uses different assets to work with and they are available under the `assets` directory. These assets include:

* Blocklists: Lists of known malicious IPs
* Keyworkds: List of keywords the program should look for on the packets' payload
* Whitelists: Lists of IPs that should be whitelisted when a connection to them happens outside of the working hours interval

Further information on how these assets are used is discussed later on this document.

## Technology Stack

Up next is the relevant information about the technologies being used on this project.

### [Rust Programming Language](https://www.rust-lang.org/)

Rust is programming language created by Mozilla with a blazing fast speed, comparable to that of C and modern features that
allow developers to create safe, fast and resource efficient code. 

Rust is a `trait` oriented programming language and has no garbage collector, instead it uses timelines and scopes to 
determine if a variable is valid, increasing performance and avoiding access to variables which value is no longer available.

Since the goal of this project is to have a really small resource usage footprint and perform efficiently to avoid affecting
the performance of the host device, this language was selected.


### [HashMap AVL](https://github.com/solotzg/rs-hash-ord)

Every list mentioned on the Assets section, is loaded into a List struct. Since these lists can countain thousands of records,
it was really important to select a good data structure that allowed fast insertions, updates and searchs. An implementation
of a HashMap with an AVL tree on every node (used to deal with hash collitions) was selected. 

While a common HashMap implementation has a very good time complexity of O(n) in the worst case scenario, under a hash
collision attack that can go up to O(n^2), on this implementation, a collision attack is only O(n log n). This is a very 
specific case and while it is not a threat under the current conditions of this project, it was decided we should plan for 
the future in case this structure was ever used on other operations.


## How it Works

The program is started by providing the name of the network interface from where the traffic will be analysed.

The Action flag can also be provided to specify what action should be performed in case anomalous activity is detected.
If no action is defined, it defaults to nothing.

Flags:
* `-I`: Shut Down Interface
* `-N`: Change Network Settings

```bash
./network-anomaly-detector-and-threat-mitigator <Interface_Name> [<Action_Flag>]
```

Examples:

```bash
./network-anomaly-detector-and-threat-mitigator eth0
```

```bash
./network-anomaly-detector-and-threat-mitigator eth0 -I
```

```bash
./network-anomaly-detector-and-threat-mitigator eth0 -N
```

Once the program is started, it will start picking up the packets on the network, analysing them and in case anomalous 
activity is detected, the provided action will be perfomed.

## How Checks are Perfomed

While checks are performed for every packet, only the packets that come from or that have as destination this host device 
(the one running this program) trigger the actions.

### Blocklisted IPs
When the program starts, all the lists of malicious IPs are loaded into a `List` and then, addresses on received packets
are checked against such list in order to detect if there was a connection to them.

### Non-Whitelisted Connections Outside of Working Hours
If a packet is received outside of working hours (defined as 7am - 10 pm), the source and destination addresses are 
checked against a whitelist. If they are on it, then the connection is considered normal and no action is taken.

### DDoS Attacks
Every time a connection is made with an IP address, its time is registered. A weight is also stored for such connection
and this weight is decreased when a connection is made with less than 500 milliseconds of difference from the last one
to the same address. If this weight reaches a certain threshold, it may indicate a DDoS attack.

The weight is increased if the connection is made with a difference of more than 500 milliseconds.

### Payload Keywords
It is known that C&C servers use certain commands to control the bots registered to their botnet. As with the blocklists
and whitelists, there's a keyword list available and loaded on runtime. When a packet is received, the contents on its 
payload are transformed into a `string` and then it checks if any of the keywords is present on that string.

## Documentation
The code has been documented and there are also diagrams available such as:

### Class Diagram
![Class Diagram](https://raw.githubusercontent.com/Hyuchia/Network-Anomaly-Detector-and-Threat-Mitigator/master/docs/Class%20Diagram.jpg)

### Functionality Process Diagram
![Functionality Process Diagram](https://raw.githubusercontent.com/Hyuchia/Network-Anomaly-Detector-and-Threat-Mitigator/master/docs/Functionality%20Process.jpg)

## Output

The following text is a sample output of the program being executed.

**Execution Command:**

```bash
./botnet-tracker wlp110s0
```

**Output:**

```
My pid is 17367
No action argument was provided, no action will be taken when detecting abnormal behaviors.
------------------------------------------------------------
Interface Information
Name: wlp110s0
IPv4: 192.168.0.110/24
IPv6: fe80::6359:2815:eeeb:3272/64
MAC: e4:a4:71:e0:fa:f6
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 33568 [Unknown]
Destination Address: 172.217.5.161
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 78
Checksum: 39682
IP Version: IPv4
Received At: 2018-11-18T04:09:25.559387868Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 0 Incoming 1 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 52558 [Unknown]
Destination Address: 172.217.5.182
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 78
Checksum: 53667
IP Version: IPv4
Received At: 2018-11-18T04:09:25.560029325Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 0 Incoming 2 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 172.217.5.182
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 52558 [Unknown]
Length: 32
Checksum: 39741
IP Version: IPv4
Received At: 2018-11-18T04:09:25.638638427Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 1 Incoming 2 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 172.217.5.161
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 33568 [Unknown]
Length: 78
Checksum: 23733
IP Version: IPv4
Received At: 2018-11-18T04:09:25.639084631Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 2 Incoming 2 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 172.217.5.182
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 52558 [Unknown]
Length: 78
Checksum: 36548
IP Version: IPv4
Received At: 2018-11-18T04:09:25.639420692Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 3 Incoming 2 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 52558 [Unknown]
Destination Address: 172.217.5.182
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 39401
IP Version: IPv4
Received At: 2018-11-18T04:09:25.679234954Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 3 Incoming 3 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 33568 [Unknown]
Destination Address: 172.217.5.161
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 41674
IP Version: IPv4
Received At: 2018-11-18T04:09:25.679745260Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 3 Incoming 4 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 44120 [Unknown]
Destination Address: 216.58.217.14
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 1108
Checksum: 34351
IP Version: IPv4
Received At: 2018-11-18T04:09:25.899888317Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 3 Incoming 5 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 44120 [Unknown]
Destination Address: 216.58.217.14
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 579
Checksum: 64683
IP Version: IPv4
Received At: 2018-11-18T04:09:25.970358908Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 3 Incoming 6 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 32
Checksum: 59947
IP Version: IPv4
Received At: 2018-11-18T04:09:25.975845407Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 4 Incoming 6 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 32
Checksum: 59327
IP Version: IPv4
Received At: 2018-11-18T04:09:25.977764803Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 5 Incoming 6 Outgoing
------------------------------------------------------------
UDP Packet
Interface: wlp110s0
Source Address: 192.168.0.1
Source Port: 41183 [Unknown]
Destination Address: 192.168.0.110
Destination Port: 137 [NetBIOS NetBIOS Name Service]
Length: 58
Checksum: 64769
IP Version: IPv4
Received At: 2018-11-18T04:09:25.979689806Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
UDP Packets - 0 Incoming 1 Outgoing
------------------------------------------------------------
UDP Packet
Interface: wlp110s0
Source Address: 192.168.0.1
Source Port: 46227 [Unknown]
Destination Address: 192.168.0.110
Destination Port: 137 [NetBIOS NetBIOS Name Service]
Length: 58
Checksum: 59469
IP Version: IPv4
Received At: 2018-11-18T04:09:25.989911806Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
UDP Packets - 0 Incoming 2 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 121
Checksum: 38709
IP Version: IPv4
Received At: 2018-11-18T04:09:26.093554608Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 5 Incoming 7 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 1432
Checksum: 528
IP Version: IPv4
Received At: 2018-11-18T04:09:26.093838630Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 5 Incoming 8 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 86
Checksum: 65273
IP Version: IPv4
Received At: 2018-11-18T04:09:26.094273175Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 5 Incoming 9 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 1432
Checksum: 28258
IP Version: IPv4
Received At: 2018-11-18T04:09:26.113495179Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 5 Incoming 10 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 350
Checksum: 54758
IP Version: IPv4
Received At: 2018-11-18T04:09:26.113830203Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 5 Incoming 11 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 117
Checksum: 3840
IP Version: IPv4
Received At: 2018-11-18T04:09:26.115546772Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 6 Incoming 11 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 198
Checksum: 20246
IP Version: IPv4
Received At: 2018-11-18T04:09:26.115763609Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 7 Incoming 11 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 44120 [Unknown]
Destination Address: 216.58.217.14
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 53088
IP Version: IPv4
Received At: 2018-11-18T04:09:26.115960318Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 7 Incoming 12 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 289
Checksum: 48630
IP Version: IPv4
Received At: 2018-11-18T04:09:26.116558787Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 8 Incoming 12 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 78
Checksum: 10535
IP Version: IPv4
Received At: 2018-11-18T04:09:26.116755851Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 9 Incoming 12 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 78
Checksum: 10515
IP Version: IPv4
Received At: 2018-11-18T04:09:26.117007436Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 10 Incoming 12 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 44120 [Unknown]
Destination Address: 216.58.217.14
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 44
Checksum: 55676
IP Version: IPv4
Received At: 2018-11-18T04:09:26.117200793Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 10 Incoming 13 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 44120 [Unknown]
Destination Address: 216.58.217.14
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 78
Checksum: 29807
IP Version: IPv4
Received At: 2018-11-18T04:09:26.117437410Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 10 Incoming 14 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 216.58.217.14
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 44120 [Unknown]
Length: 32
Checksum: 58435
IP Version: IPv4
Received At: 2018-11-18T04:09:26.123984508Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 11 Incoming 14 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.0.78.13
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 51272 [Unknown]
Length: 26
Checksum: 28275
IP Version: IPv4
Received At: 2018-11-18T04:09:26.158068181Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 12 Incoming 14 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.0.78.13
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 51272 [Unknown]
Length: 55
Checksum: 35120
IP Version: IPv4
Received At: 2018-11-18T04:09:26.158292159Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 13 Incoming 14 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 20
Checksum: 25684
IP Version: IPv4
Received At: 2018-11-18T04:09:26.158473087Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 13 Incoming 15 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.0.78.13
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 51272 [Unknown]
Length: 26
Checksum: 26498
IP Version: IPv4
Received At: 2018-11-18T04:09:26.158668779Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 14 Incoming 15 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 1264
Checksum: 64319
IP Version: IPv4
Received At: 2018-11-18T04:09:26.197488240Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 14 Incoming 16 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.0.78.13
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 51272 [Unknown]
Length: 188
Checksum: 27781
IP Version: IPv4
Received At: 2018-11-18T04:09:26.288320646Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 15 Incoming 16 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 51272 [Unknown]
Destination Address: 192.0.78.13
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 20
Checksum: 25494
IP Version: IPv4
Received At: 2018-11-18T04:09:26.288993248Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 15 Incoming 17 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 2824
Checksum: 6122
IP Version: IPv4
Received At: 2018-11-18T04:09:26.294363284Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 16 Incoming 17 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 56876
IP Version: IPv4
Received At: 2018-11-18T04:09:26.296157440Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 16 Incoming 18 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 8914
IP Version: IPv4
Received At: 2018-11-18T04:09:26.300540042Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 17 Incoming 18 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 51286
IP Version: IPv4
Received At: 2018-11-18T04:09:26.303132814Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 17 Incoming 19 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 25666
IP Version: IPv4
Received At: 2018-11-18T04:09:26.303734191Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 18 Incoming 19 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 28950
IP Version: IPv4
Received At: 2018-11-18T04:09:26.306043293Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 18 Incoming 20 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 8914
IP Version: IPv4
Received At: 2018-11-18T04:09:26.311387849Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 19 Incoming 20 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 23355
IP Version: IPv4
Received At: 2018-11-18T04:09:26.313722998Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 19 Incoming 21 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 13102
IP Version: IPv4
Received At: 2018-11-18T04:09:26.314131648Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 20 Incoming 21 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 13581
IP Version: IPv4
Received At: 2018-11-18T04:09:26.316078343Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 20 Incoming 22 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 14498
IP Version: IPv4
Received At: 2018-11-18T04:09:26.316637566Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 21 Incoming 22 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 2411
IP Version: IPv4
Received At: 2018-11-18T04:09:26.318268175Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 21 Incoming 23 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 22874
IP Version: IPv4
Received At: 2018-11-18T04:09:26.318618710Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 22 Incoming 23 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 48401
IP Version: IPv4
Received At: 2018-11-18T04:09:26.320341217Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 22 Incoming 24 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 4062
Checksum: 18686
IP Version: IPv4
Received At: 2018-11-18T04:09:26.320777766Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 23 Incoming 24 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 33043
IP Version: IPv4
Received At: 2018-11-18T04:09:26.322146825Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 23 Incoming 25 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 2824
Checksum: 6122
IP Version: IPv4
Received At: 2018-11-18T04:09:26.322401275Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 24 Incoming 25 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 30250
IP Version: IPv4
Received At: 2018-11-18T04:09:26.323306378Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 24 Incoming 26 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 74.125.1.72
Source Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Destination Address: 192.168.0.110
Destination Port: 43104 [Unknown]
Length: 2824
Checksum: 6122
IP Version: IPv4
Received At: 2018-11-18T04:09:26.323542300Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 25 Incoming 26 Outgoing
------------------------------------------------------------
TCP Packet
Interface: wlp110s0
Source Address: 192.168.0.110
Source Port: 43104 [Unknown]
Destination Address: 74.125.1.72
Destination Port: 443 [Hypertext Transfer Protocol over TLS/SSL (HTTPS)]
Length: 32
Checksum: 27450
IP Version: IPv4
Received At: 2018-11-18T04:09:26.324322404Z
Connection to Non Authorized IP During Non Working Hours
------------------------------------------------------------
TCP Packets - 25 Incoming 27 Outgoing
------------------------------------------------------------

```
