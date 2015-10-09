import dpkt, pcap
import re
import sys
import binascii
import copy
import struct

class TCPRetransmit:
	interface = None;
	capture_filter = "tcp";
	
	def __init__(self, iface=None, filter="tcp"):
		self.interface = iface;
		self.capture_filter = filter;
		
	def Send(self, data_bytes, target):
		target_bytes = self.n_to_a(target);
		pc = pcap.pcap(self.interface);
		pc.setfilter(self.capture_filter);
		print "listening on %s" % (pc.name);
		decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
			pcap.DLT_NULL:dpkt.loopback.Loopback,
			pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()];
                
		offset = 0;
                
		for ts, pkt in pc:
			print ts;
			ethPkt = decode(pkt);
			if (type(ethPkt) != dpkt.ethernet.Ethernet):
				print "Not ethernet packet, cannot use";
				continue;
			
			print "Got ethernet packet from "+self.format_mac(ethPkt.src)+" to "+self.format_mac(ethPkt.dst);
			if (type(ethPkt.data) != dpkt.ip.IP):
				print "Not IPv4 data, cannot use";
				continue;
				
			ipPkt = ethPkt.data;
			print " - IP Traffic: "+self.format_ip(ipPkt.src)+" -> "+self.format_ip(ipPkt.dst);
			
			#print ipPkt.src;
			#print int(ipPkt.dst);
			#print target_bytes;
			#print ' '.join('%02X' % int(x));
			#print ' '.join('%02X' % int(x) for x in ipPkt.dst);
			#print ' '.join('%02X' % x for x in target_bytes);
			if (ipPkt.dst != target_bytes):
				print " - Not our target";
				continue;
			
			
			if (type(ipPkt.data) == dpkt.tcp.TCP):
				packet_size = len(ipPkt.data.data);
				buffer_size = len(data_bytes);
				print "    - TCP Traffic";
				if (packet_size == 0):
					print "    - Zero size, discarding";
					continue;
					
				print "    - Ethernet Frame Size: "+str(len(ethPkt));
				print "    - TCP Packet Size: "+str(packet_size);
				print "    - Remaining Queue: "+str(buffer_size-offset);
				if (buffer_size-offset < packet_size):
					data = data_bytes[offset:];
					for i in xrange(0, (packet_size-(buffer_size-offset))-1):
						data.append(0x00);
				else:
					data = data_bytes[offset:(offset+packet_size)];
					
				offset += packet_size;
				
				ipPkt.data.data = data;
				print "    - Original checksum: 0x%04x" % ipPkt.data.sum;
				ipPkt.data.sum = self.generate_tcp_checksum(ipPkt);
				print "    - Our checksum: 0x%04x" % ipPkt.data.sum;
				print "    - Our Length: %d" % len(data); 
				
				#Mess up the data
				out_data = [];
				for i in xrange(0, len(data)):
					out_data.append(data[i] ^ ((ipPkt.data.sum >> ((i % 2)*8)) & 0xff));
				ipPkt.data.data = bytearray(out_data);
				
				print ' '.join('%02X' % x for x in data);
				print '%02X' % ipPkt.data.sum;
				print ' '.join('%02X' % x for x in out_data);
				
				ethPkt.data = ipPkt;
				#raw_frame = ipPkt.pack();
				raw_frame = ethPkt.pack();
				pc.inject(raw_frame, len(raw_frame));
				if (offset >= buffer_size):
					print "ALL BYTES SENT";
					return;
				
				
						
			if (type(ipPkt.data) == dpkt.udp.UDP):
				print " - UDP Traffic, cannot use (yet)";
			else:
				print " - Not TCP Traffic, cannot use";
		
		
	def Receive(self, callback):
		pc = pcap.pcap(self.interface);
		pc.setfilter(self.capture_filter);
		print "listening on %s" % (pc.name);
		decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
			pcap.DLT_NULL:dpkt.loopback.Loopback,
			pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()];
               
		for ts, pkt in pc:
			print ts;
			ethPkt = decode(pkt);
			if (type(ethPkt) != dpkt.ethernet.Ethernet):
				print "Not ethernet packet, cannot use";
				continue;
			
			print "Got ethernet packet from "+self.format_mac(ethPkt.src)+" to "+self.format_mac(ethPkt.dst);
			if (type(ethPkt.data) != dpkt.ip.IP):
				print "Not IPv4 data, cannot use";
				continue;
				
			ipPkt = ethPkt.data;
			print " - IP Traffic: "+self.format_ip(ipPkt.src)+" -> "+self.format_ip(ipPkt.dst);
			
			if (type(ipPkt.data) == dpkt.tcp.TCP):
				print "    - TCP Traffic";
				
				tcpPkt = ipPkt.data;
				
				if (len(tcpPkt.data) == 0):
					print "    - Zero size, discarding";
					continue;
				
				
				rcv_sum = tcpPkt.sum;
				gen_sum = self.generate_tcp_checksum(ipPkt);
				print "    - Packet Checksum: 0x%04x" % rcv_sum;
				print "    - Our Checksum: 0x%04x" % gen_sum;
				if (rcv_sum != gen_sum):
					print "    - Bad Checksum: Trying for data";
					data = self.try_tcp_unxor(ipPkt);
					if (data == None):
						print "    - XOR Checksum does not match";
						continue;
					print "    - XOR Checksum Match: FOUND DATA!";
					callback(data);
						
			elif (type(ipPkt.data) == dpkt.udp.UDP):
				print " - UDP Traffic, cannot use (yet)";
			else:
				print " - Not TCP Traffic, cannot use";
				
	
	def format_mac(self, mac_addr) :
		mac_addr = binascii.hexlify(mac_addr);
		"""This function accepts a 12 hex digit string and converts it to a colon separated string"""
		s = list()
		for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
			s.append( mac_addr[i*2:i*2+2] )
		r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
		return r
	
	def format_ip(self, ip):
		ba_ip = bytearray(ip);
		return str(int(ba_ip[0]))+"."+str(int(ba_ip[1]))+"."+str(int(ba_ip[2]))+"."+str(int(ba_ip[3]));
		
	def generate_tcp_checksum(self, ipPkt):
		tcpPktCopy = copy.deepcopy(ipPkt.data);
		tcpPktCopy.sum = 0;
		tcp_bytes = bytearray(tcpPktCopy.pack());
		psudoheader = dpkt.struct.pack('>4s4sxBH', ipPkt.src, ipPkt.dst,
                                     ipPkt.p, len(tcp_bytes));
                tcp_bytes = psudoheader+tcp_bytes;
		
		newsum = 0;
		for i in xrange(0, len(tcp_bytes), 2):
			#1 word = 2 bytes
			
			if (i+1 == len(tcp_bytes)):
				##If Odd number of bytes, RFC 793 says pack on the right
				word = tcp_bytes[i] << 8;
			else:
				word = tcp_bytes[i+1] + (tcp_bytes[i] << 8);
			#carry around add
			c = newsum + word;
			newsum = (c & 0xffff) + (c >> 16);
		num = ~newsum & 0xffff;
		return num;
		
	def try_tcp_unxor(self, ipPkt):
		ipPktCopy = copy.deepcopy(ipPkt);
		tcpPkt = ipPkt.data;
		tcpPktCopy = ipPktCopy.data;
		out_data = [];
		data = bytearray(tcpPkt.data);
		for i in xrange(0, len(data)):
			out_data.append(data[i] ^ ((tcpPkt.sum >> ((i % 2)*8)) & 0xff));
		
		
		tcpPktCopy.data = bytearray(out_data);
		ipPktCopy.data = tcpPktCopy;
		
		if (self.generate_tcp_checksum(ipPktCopy) == ipPkt.data.sum):
			return out_data;
		else:
			return None;
	
	def n_to_a(self, name):
		s = name.split(".");
		return chr(int(s[0]))+chr(int(s[1]))+chr(int(s[2]))+chr(int(s[3]));
#class TCPDodgyPacket:
	
