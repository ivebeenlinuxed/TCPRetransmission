import sys;
import os;
sys.path.append(os.path.abspath(os.path.dirname(os.path.realpath(__file__))+"/../"));
from transmission.TCPRetransmit import TCPRetransmit;

def found_data(data):
	print "FOUND DATA!";
	s = "";
	for ch in data:
		s += chr(ch);
	print s;
	sys.exit(0);

tcp = TCPRetransmit("br0", "tcp");
tcp.Receive(found_data);
