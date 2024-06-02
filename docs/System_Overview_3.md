
After the 10 seconds expires, the leaf node sends out *x* calibration packets, where *x* is the number that was given by the root node. These packets are sent every *n* milliseconds, as specified during the pairing phase. These packets are addressed to the link-local address of IPv6 and pairing port, and contain very simple information so as to avoid constructing and deconstructing a complicated packet at each node:
```
{
    type: calibration,
    noise: -93,
    packets_remaining: 87,
}
```
<sub>An example of a calibration packet sent from a leaf node to a root. Note the `packets_remaining` field, which tells us how many calibration packets the leaf has yet to send. </sub>

Because of the address and port used to address these packets, they will be seen by the other leaves. However, instead of having these leafs receive these messages on their IPv6 socket that is listening on the pairing port, the leaves use the capture handles they have opened through the [pcap library](https://www.tcpdump.org/manpages/pcap.3pcap.html) to "sniff" the packets as they are sent from their siblings. As these packets are intercepted, the Radiotap header added on the packet when received is dissected and the RSSI (or signal strength) is extracted from the packet. However, because of the ever-changing landscape that is network conditions, the leaf will not inform the root that it has successfully received the RSSI from it's sibling until the number of remaining packets is 0. This allows us to average the RSSI values, so as to use a more accurate distance between the leaf and it's siblings. 

Once the `packets_remaining` field has dropped to 0, the sibling will then send a confirmation to the root indicating that it has successfully received the distance. Should a sibling not have successfully received any of the packets, it will set the confirmation to false so that the root can ask the leaf that was sending out the packets to resend it's data. An example of a leaf indicating successful estimation of the distance between itself and it's sibling is below:

```
{
    type: calibration,
    noise: -87,
    leaf:  fe80::603e:5fff:fe62:1556, 
    confirmation: true
}

```
<sub>An example of a confirmation calibration packet sent from a leaf node to a root. Note the `leaf` field, which has the IPv6 address of the sibling the leaf was listening for, **not** the IPv6 address of the leaf sending the confirmation packet.</sub>

After receiving a confirmation from each of the leaves, the root then sends out a new calibration packet, just like [before](#link_to_calibration_packets), except with a different IPv6 address, which indicates a different leaf that needs to send data so it's siblings can register it's location. This process repeats for each leaf until each leaf has an accurate distance between it and it's siblings. This data is then passed along to the root at **the end of the calibration phase**, which allows the root to have proper measurements for the device location phase. 

- [ ] : Add packet for sending distances here

##### Smart Device Discovery Phase

- This may need to be skipped/hardcoded at first.

##### User Tracking and Automation Phase

Once all smart devices have been registered to the system, the system enters it's primary phase, which involves both **tracking the user** and **responding to movement**. 

**Note: this should be under explanation for leaf node, but I haven't created that yet.**

Here, we've chosen to break down the order of explanation as based upon a "packet flow" - in other words, this part of the documentation will diagram the system's response when it captures a packet using it's packet handler.

First, the system will capture a packet that comes over the network. Upon receiving the packet, the system will parse the packet and look for it's Radiotap header. Once the Radiotap header is located, the RSSI is extracted and saved to a variable. Then, the system looks for the MAC address of the device who sent the packet. The MAC address, once found, is first compared to a list of blocked devices. This device list, which is determined by the root and communicated from the root to the leaves, represents devices which the system has already determined to be *ineligible for user tracking*. This means that after a candidate period of 24 hours, the system did not detect sufficient movement or variation of location of the device, which means that it likely is a stationary device - not a device the user often uses and carries with them. 

Assuming that the MAC address is not in our block list, the system then looks for the address in our *candidate list*. Devices in this list belong to one of two categories: **candidate** or **permanent**. Permanent devices represent devices that have been tracked by the system for a period *t* (where *t* >= 24 hours) and have been determined to be indicative of user activity. Should the device be present in our candidate list, the distance of the device from the node is immediately calculated, and that distance data (along with the MAC address) is passed to the socket for communication with the root. 

Should the device not be present in our candidate list, the system will then check whether it is present in our *trial list*. The trial list is described in more detail on the next page, however, suffice it to say that if the device is in our trial list, the distance is calculated and both the distance and MAC address are passed to the socket for communication with the root.

If the device is *not* present in either the candidate or trial list, then the system looks for one final piece of information: the OUI[^1]. If OUI is not located in the packet, the packet is dropped and the system begins looking for other packets. If it is, the OUI is compared to a list of OUI's which represent the OUI's associated with companies that primarily manufacture user devices. If the OUI matches any of these companies, the device's distance from the leaf is calculated and the address and distance are passed to the socket to be communicated with the root. However, the device is **not** added to our candidate list yet.  

[Continue](./System_Overview_4.md)

[^1]: For more information on OUI, please visit [this link](https://standards.ieee.org/faqs/regauth/) and look under the "What is a Organizationally Unique Identifier (OUI)?".