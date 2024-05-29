# VM03 - Web server víctima
## 1. Instalación de ubuntu-server
Instalar ubuntu-server 22.04.4 y actualizar el sistema operativo.
```bash
sudo apt update
sudo apt upgrade
```

## 2. Configuración de red
Editamos el fichero de configuración de red `/etc/network/interfaces` para que tenga el siguiente contenido:
```bash
auto lo
iface lo inet loopback

# RLAB - VLAN 799 - IP Lab48 por DHCP
auto ens18
iface ens18 inet dhcp

# RINT - VLAN 798 - Red interna
auto ens19
iface ens19 inet static
      address 10.2.2.3
      netmask 255.255.255.0
```

Reiniciamos el servicio de red para aplicar los cambios realizados.
```bash
sudo systemctl restart networking.service
```

Deberíamos de tener la siguiente configuración de red:
```bash
root@vm03:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:48:03 brd ff:ff:ff:ff:ff:ff
    altname enp0s18
    inet 10.0.48.3/18 brd 10.0.63.255 scope global dynamic ens18
       valid_lft 1304sec preferred_lft 1304sec
3: ens19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:98:48:03 brd ff:ff:ff:ff:ff:ff
    altname enp0s19
    inet 10.2.2.3/24 brd 10.2.2.255 scope global ens19
       valid_lft forever preferred_lft forever
```

## 3. Instalar docker
Instalar docker en la versión `24.0.5`.
```bash
sudo apt-get install docker.io
```

Comprobamos que la versión de docker es la `24.0.5`.
```bash
root@vm03:~# docker -v
Docker version 24.0.5, build 24.0.5-0ubuntu1~22.04.1
```

Añadimos al usuario `usuario` al grupo de `docker`, para que este pueda usar docker sin problemas.
Esto se hace modificando esta línea en el fichero de configuración `/etc/group`.
```bash
docker:x:120:usuario
```

Reiniciamos los servicios de docker para evitar conflictos con el siguiente comando.
```bash
systemctl restart docker.service docker.socket
```
## 4. Despliegue de Servidor Web vulnerable (DVWA)
Para desplegar el servidor web vulnerable con docker utilizamos el siguiente comando:
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Para acceder a la aplicación desde una máquina de la misma red ponemos en el navegador la url `http://192.168.1.23`.
Nos saldrá un panel de login para acceder a la aplicación web introducimos el usuario `admin` y la contraseña `password`.
![DVWA Login](https://github.com/zerebritvs/TFG/tree/main/images/dvwaLogin.png)

Entramos en la web y seleccionamos el botón que aparece abajo del todo `Create / Reset Database` para inicializar la base de datos.
![DVWA Setup](https://github.com/zerebritvs/TFG/tree/main/images/dvwaSetup.png)

Nos sacará de la web y nos volverá a pedir las credenciales anteriores en el panel de login.
![DVWA Login](https://github.com/zerebritvs/TFG/tree/main/images/dvwaLogin.png)

Y ya estaremos dentro de la aplicación web lista para funcionar.
![DVWA Home](https://github.com/zerebritvs/TFG/tree/main/images/dvwaHome.png)

Para que no salga esto en File Inclusion (`allow_url_include`): 
```bash
sudo docker exec dvwa sed -i 's/allow_url_include = Off/allow_url_include = On/g' /etc/php/7.0/apache2/php.ini 
sudo docker exec dvwa /etc/init.d/apache2 reload
```