# ARP-poisoning-packet-sniffer
Aynı ağda bulunan hedef bilgisayarlar üzerinde ARP zehirlemesi(poisoning) yapmak ve ağ trafiğini izlemenizi sağlamak için yazılmış iki scripttir.



**arp_spoofy.py** script'i aynı ağda bulunan hedef bilgisayar üzerinde ARP zehirlemesi yapmak için kullanılan bir scripttir.


**arp_spoofy.py** script'i hedef bilgisayar üzerinde ARP zehirlemesi yaparken **paket_sniffer.py** script'i de aynı anda http isteklerini dinlemeye alarak olası kullanıcı adı / parola girişlerini görüntüler.


### ARP Spoof Kullanımı
python arp_spoof.py --hedef **HEDEFIP** --gateway **GATEWAY**

### Packet Sniffer Kullanımı
python packet_sniffer.py --interface **ARAYUZ**



### ARP Spoof Örnek Kullanım
python arp_spoof.py --hedef 10.0.2.15 --gateway 10.0.2.1


### Packet Sniffer Örnek Kullanım
python packet_sniffer.py --interface wlan0


