#!/usr/bin/env python3



"""
This is a DNS sniffer coded in Python by @amezolaMartin. It uses Scapy library. 

Usage:

In order to sniff DNS traffic we need to be in the middle of the conection between the victim and the router so, we first need to poison the ARP tables of both vicim and router. That can be done using the
arpspoofer tool, or using the arp_spoofer.py file i coded which can be accessed in my github page:

Link: https://github.com/amezolaMartin/simple_arp_spoofer

python dns_sniffer.py -t <target_ip>
"""


import scapy.all as scapy
from termcolor import colored


def prc_dns_packet(packet):
	#print(packet.show()) this shows dns packet content

	if packet.haslayer(scapy.DNSQR): # Filter only dns packets that have DNS Query Record layer. (With qname)
		
		# get domain from dns packet
		domain = packet[scapy.DNSQR].qname.decode()

		# i will create a blacklist of dns keywords in order to make the output cleaner 
		dns_blacklist = ["google", "cloudfare", "bing", "static", "sensic"]

		if domain not in domains_set and not any(keyword in domain for keyword in dns_blacklist): # if the domain is new and doesnt mach with blacklist keywords
			# Print and add to domain set
			print(colored(f"\n[+] Domain name: {domain}", "green"))
			domains_set.add(domain) # Python sets already manage to prevent repetitions so i dont need to see if its already in domain_set i just add it


def main():
	interface = "eth0" #Change THIS to the interface you're using (ex: eth2, eth3, ens32, enp0s3,...)
	print(f"\n[+] Intercepting DNS packets from victim...\n")

	# Create a set to store domains (a list can be used but i don't want repeated domains)
	global domains_set # Make it global so it can be seen from function prc_dns_packet
	domains_set = set()

	# We use filter udp and port 53 bcoz thats what dns requests use
	scapy.sniff(iface=interface, filter="udp and port 53", prn=prc_dns_packet, store=False)
	# prc_dns_packet() to process the dns packet instantly
	# store = False so it doesn't store it

if __name__ == "__main__":
	main()




