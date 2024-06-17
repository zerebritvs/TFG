# VM02 - Kali atacante
## 1. Instalación de ubuntu-server
Instalar ubuntu-server 22.04.4 y actualizar el sistema operativo.
```bash
sudo apt update
sudo apt upgrade
```

## 2. Configuración de red
Editamos el fichero de configuración de red `/etc/network/interfaces` para que tenga el siguiente contenido.
```bash
auto lo
iface lo inet loopback

# RLAB - VLAN 799 - IP Lab48 por DHCP
auto eth0
iface eth0 inet dhcp

# RINT - VLAN 798 - Red interna
auto eth1
iface eth1 inet static
      address 10.2.2.2
      netmask 255.255.255.0
```

Reiniciamos el servicio de red para aplicar los cambios realizados.
```bash
sudo systemctl restart networking.service
```

Deberíamos de tener la siguiente configuración de red.
```bash
root@vm03:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:48:02 brd ff:ff:ff:ff:ff:ff
    altname enp0s18
    inet 10.0.48.2/18 brd 10.0.63.255 scope global dynamic ens18
       valid_lft 1304sec preferred_lft 1304sec
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:98:48:02 brd ff:ff:ff:ff:ff:ff
    altname 
    inet 10.2.2.3/24 brd 10.2.2.255 scope global ens19
       valid_lft forever preferred_lft forever
```