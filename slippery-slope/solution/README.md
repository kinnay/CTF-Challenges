Slippery Slope
==============

The player is provided with a monitor-mode capture of two people playing Super Mario Maker 2 in local wireless mode (LDN). The goal is to decrypt the traffic and find the flag.

The following steps are required to solve the challenge:
* Find an decrypt the action frame that contains information about the wireless network.
* Derive the correct encryption key and use this to decrypt the data frames (this is standard 802.11).
* Parse the network protocol headers (LLC/SNAP/IPv4/UDP) to obtain the data that is transmitted by the game.
* Derive the P2P session key and use this to decrypt the packets.
* Find the flag.

The following resources may be useful:
* [Implementation of the LDN protocol in Python](https://github.com/kinnay/ldn)
* [Documentation about the LDN protocol](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol)
* [Independent documentation about the LDN protocol](https://switchbrew.org/wiki/LDN_services#Network_protocol)
* [Documentation about the Pia protocol](github.com/kinnay/NintendoClients/wiki/Pia-Protocol)
* [Super Mario Maker 2 level format](https://github.com/liamadvance/smm2-documentation/blob/master/Course%20Format.md)
