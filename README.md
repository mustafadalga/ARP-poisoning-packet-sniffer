# ARP Poisoning - Packet Sniffer

#### Aynı ağda bulunan hedef bilgisayarlar üzerinde ARP zehirlemesi(poisoning) yapmak ve ağ trafiğini izlemenizi sağlamak için yazılmış iki scripttir.



* **arp_spoofy.py** script'i aynı ağda bulunan hedef bilgisayar üzerinde ARP zehirlemesi yapmak için kullanılan bir scripttir.

* **arp_spoofy.py** script'i hedef bilgisayar üzerinde ARP zehirlemesi yaparken **paket_sniffer.py** script'i de aynı anda http isteklerini dinlemeye alarak olası kullanıcı adı / parola girişlerini görüntüler.


#### Kurulacak modüller

* Linux için kurulum
```
sudo pip install -r requirements.txt
```


### ARP Spoof Kullanımı

```
python arp_spoof.py --hedef HEDEFIP --gateway GATEWAY
```

### Packet Sniffer Kullanımı
```
python packet_sniffer.py --interface ARAYUZ
```


### ARP Spoof Örnek Kullanım
```
python arp_spoof.py --hedef 10.0.2.15 --gateway 10.0.2.1
```

### Packet Sniffer Örnek Kullanım
```
python packet_sniffer.py --interface wlan0
```


### Arp Spoofing
![arp](https://user-images.githubusercontent.com/25087769/58845258-29b3d580-8683-11e9-8fd4-437720c2c57a.PNG)


### Packet Sniffer
![packet](https://user-images.githubusercontent.com/25087769/58845259-29b3d580-8683-11e9-9ae5-2b7d84e0c27a.PNG)



### Yakalanan Olası Giriş Bilgileri 
![request-response](https://user-images.githubusercontent.com/25087769/58845260-29b3d580-8683-11e9-9332-040b1e79ae94.PNG)


