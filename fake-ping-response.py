"""
Route every IP that you want as below, for example 8.8.8.8:
	sudo route add -net 8.8.8.8 netmask 255.255.255.255 FakePing

Also, undo the change by:
	sudo route del -net 8.8.8.8 netmask 255.255.255.255 FakePing

Result:
	PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
	64 bytes from 8.8.8.8: icmp_seq=1 ttl=2 time=1009 ms
	64 bytes from 8.8.8.8: icmp_seq=2 ttl=2 time=1007 ms
	64 bytes from 8.8.8.8: icmp_seq=3 ttl=2 time=1009 ms
	64 bytes from 8.8.8.8: icmp_seq=4 ttl=2 time=1007 ms
"""

desire_ttl = 2
desire_time = 1

#################################################################

import select
import time
from scapy.all import IP, ICMP
from pytun import TunTapDevice, IFF_TAP, IFF_TUN, IFF_NO_PI

tun = TunTapDevice(flags=IFF_TUN|IFF_NO_PI, name="FakePing")
tun.addr = "10.10.10.1"
tun.netmask = '255.255.255.0'
tun.up()

epoll = select.epoll()
epoll.register(tun.fileno(), select.EPOLLIN)

while True:
	while epoll.poll(0):
		data = tun.read(tun.mtu)
		packet = IP(data)
		
		icmp_part = packet.getlayer(ICMP)
		if icmp_part is not None:
			time.sleep(desire_time)
			respacket = IP(src=packet.dst, dst=packet.src, ttl=desire_ttl)
			respacket/=ICMP(type=0, seq=icmp_part.seq, id=icmp_part.id)
			respacket/=icmp_part.payload
			tun.write(bytes(respacket))
			
			packet.show()
			respacket.show()

	time.sleep(0.01)

