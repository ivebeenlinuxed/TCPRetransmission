# Hiding data in TCP retransmissions

After a certain amount of thought I have decided to release my first draft of an application designed to send data anonymously and descreatly over a network. The application utilises the ability for TCP to retransmit data that the remote host has not aknowledged.

This version of the code, a proof of concept, utilises the Python, pcap and dpkt, and has a client/server interface.

The server’s role is to listen for packets either on the outgoing interface, or that our visible to the adapter, which are already being delivered to the target host. When a packet is found, who’s destination matches the target, another packet is constructed, of the same length with the payload data inside of it.

To try to disguise the data, the new packet is checksum’d and the checksum then XOR’d. This has two advantages. First of all, even if a packet were to arrive first (due to for example different routes being chosen), the packet is dropped by the operating system (because of the now bad checksum), before delivery thus making the attempt invisible to the application. Secondly it allows the client application to easily distinguish packets which are sent for it - if the XOR of the checksum then matches the packet, it is data that we want.

The client then simply listens on the interface to traffic, where the checksum is wrong. If it is wrong, it XORs the checksum and sees if the new checksum now matches the packet.

The data is then fed out to an application that processes it.

Because the information is sent through standard error correction channels, through an existing TCP connection, most firewalls will allow it to pass. The only problem with this first draft is the XOR checksum. This is because NAT devices will drop packets with bad checksums, as there is no reason to transmit a corrupt packet on. There are various other means of checking the packets however still using the concept of TCP retransmission as a cover.
