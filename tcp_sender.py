import sys;
import os;
sys.path.append(os.path.abspath(os.path.dirname(os.path.realpath(__file__))+"/../"));
from transmission.TCPRetransmit import TCPRetransmit;


tcp = TCPRetransmit("wlan0", "tcp port 80");
tcp.Send(bytearray("Hello World"), "xxx.xxx.xxx");
