These are communicated to the leaf node using the LML protocol, and the parent specifically communicates these to the node using it's IPv6 address (given by the pairing packet that was sent to the root) and the pairing port. An example of this response is below:
```
{
 type: pairing,
 noise: -73, 
 port_to_communicate: 27888,
 interval: 100 
}
```
<sub>Please note that noise is measured in decibals (dB), and the interval for communication is measured in milliseconds (ms).</sub>

Upon receiving this response, the child will send a confirmation packet over the **pairing port** that is formatted like so: 
```
{
 type: pairing,
 noise: -64,
 confirmation: true
}
```
The `confirmation` field informs the root that data was received successfully and the leaf node is ready to begin communicating using the methods specified by the root. 

Upon receiving confirmation, the root will create a thread which creates the socket used to communicate with that specific leaf nonde. It will also create a shared memory buffer with the thread, allowing for data to be passed back and forth between the threads. This means that location data communicated by the leaf will be accessible by the root, and the root can place data that needs to be communicated to that child in the buffer. 

The root will repeat this pairing process until 3 leaves are paired. Thus, at the end of this stage, the root should have: **4 threads** (one for each of the leaf nodes and one for the root itself), **4 sockets** (one for each leaf node and one left over from the pairing phase), and **3 shared memory buffers** (one for each leaf to communicate data to and receive data from the root). Each of these threads is assigned an equal priority n where n <= 98 and set to the SCHED_RR scheduling algorithm, so that the root thread always runs before them and can send data to the children, or receive data from the children that was placed in their respective memory buffers during their last run.[^1]

##### Sniffer Establishment

In order to proceed with tracking devices using the signal strength, we must be able to quantifiably measure the RSSI. However, there isn't a reliable way to do this using sockets. In order to properly measure this, we choose to utilize the Radiotap header that is added when capturing packets in monitor mode. 

However, we can't sacrifice communication between the root and the leaf nodes, and placing a NIC in monitor mode causes the NIC to diassociate from the network. In order to maintain connections between the nodes, we have purchased three antennas with their own NIC's, each capable of monitor mode. Each antenna will be connected to a Raspberry Pi "leaf", which gives each Pi **two** NIC's instead of the standard one. This allows us to place one NIC in monitor mode (which allows us to continually monitor the network and capture all packets being transmitted near the Pi) and reserve the other NIC for communication between itself and the other leaves. 

For more details on how these capture sessions are created and facilitated, click [here](). 

##### Calibration Phase {#calibrate}

After pairing with the root, the distance of each leaf from each other must be determined in order to properly perform triangulation and accurately determine the location of both user and smart devices. However, pushing this responsibility onto the leaf nodes introduces both unnecessary levels of complexity and would likely result in more congestion on the network. Because of this, we choose to have the root node utilize the already existing communication channels that were established during the pairing process to coordinate each node and have all nodes receive the data needed. 

Upon entering this phase, the root will first send out a calibration packet as specified by the LML protocol. This packet is sent over the pairing socket (ensuring that every child is able to see it) and contains both the amount of packets to send over the pairing socket and the IPv6 address of the leaf node we want to communicate first. **Important note:** while the packet contains the IPv6 address of the leaf node, the packet is addressed to every node. This means that the packet uses the link-local address of IPv6 (ff02:1) and the pairing port to ensure every node receives the message and knows who is going to send their location data first.
#### {#link_to_calibration_packets}
```
{
    type: calibration, 
    num_of_calibration_packets: 100,
    leaf: fe80::603e:5fff:fe62:1556
}
```
<sub>An example of a LML calibrate packet from a root node to a leaf node.</sub>

Upon receiving the calibration packet, a leaf node waits for a total of 10 seconds before sending out response calibration packets. This allows it's "siblings" to save the IPv6 address of that node into their local database, and prepare to measure the distance between them and their sibling. 

[Continue](./System_Overview_3.md)

[^1]: Documentation for the functions used to control CPU scheduling can be found [here](https://man7.org/linux/man-pages/man7/sched.7.html).