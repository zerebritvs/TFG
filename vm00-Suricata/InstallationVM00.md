# VM00 - Suricata
## 1. Instalación de ubuntu-server
Instalar ubuntu-server 22.04.3 y actualizar el sistema operativo.
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
auto ens18
iface ens18 inet dhcp

# RINT - VLAN 798 - Red interna, tarjeta de escucha
auto ens19
iface ens19 inet manual
#      address 10.2.2.80
#      netmask 255.255.255.0
      up ip link set ens19 promisc on

# RLAB2 - VLAN709 - IP Lab27 por DHCP
auto ens20
iface ens20 inet dhcp
      up ip link set ens20 promisc on

# RLAB3 - VLAN 799 - LAB27 INTERNA
auto ens21
iface ens21 inet static
      address 10.2.1.80
      netmask 255.255.255.0
      up ip link set ens21 promisc on

# RINT - VLAN 798 - Red interna
auto ens22
iface ens22 inet static
      address 10.2.2.80
      netmask 255.255.255.0
```

Reiniciamos el servicio de red para aplicar los cambios realizados.
```bash
sudo systemctl restart networking.service
```

Deberíamos de tener la siguiente configuración de red.
```bash
usuario@vm00:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s18
    inet 10.0.48.250/18 brd 10.0.63.255 scope global dynamic ens18
       valid_lft 1031sec preferred_lft 1031sec
3: ens19: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:98:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s19
4: ens20: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:27:80 brd ff:ff:ff:ff:ff:ff
    altname enp0s20
    inet 10.0.27.80/18 brd 10.0.63.255 scope global dynamic ens20
       valid_lft 1174sec preferred_lft 1174sec
5: ens21: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:99:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s21
    inet 10.2.1.80/24 brd 10.2.1.255 scope global ens21
       valid_lft forever preferred_lft forever
6: ens22: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:01:27:98:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s22
    inet 10.2.2.80/24 brd 10.2.2.255 scope global ens22
       valid_lft forever preferred_lft forever
```
## 3. Instalar Suricata
Para instalar Suricata, primero hay que añadir el repositorio de paquetes de la Open Information Security Foundation (OISF) al servidor.
```bash 
sudo add-apt-repository ppa:oisf/suricata-stable
```

Instalamos Suricata.
```bash
sudo apt install suricata
```

Suricata almacena su configuración en el archivo `/etc/suricata/suricata.yaml`. El modo por defecto de Suricata es el Modo IDS (Sistema de Detección de Intrusos), en el que sólo se registra el tráfico y no se detiene. También existe la posibilidad de configurarlo en modo IPS (Intrusion Prevention System).

### 3.1. Configurar las redes para Suricata
Añadiremos las redes que queremos que sean monitoreadas, así como lo que queramos que se considere red externa y añadimos el servidor HTTP que habrá en el laboratorio.
```yml
##
## Step 1: Inform Suricata about your network
##

vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[10.0.27.0/18,10.2.1.0/24,10.2.2.0/24]"

    EXTERNAL_NET: "!$HOME_NET"

    HTTP_SERVERS: "10.2.2.3/24"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
```

### 3.2. Activar ID de Comunidad
El campo ID de Comunidad facilita la correlación de datos entre registros generados por distintas herramientas de monitorización. Dado que utilizaremos Suricata con Elasticsearch, habilitar el ID de Comunidad puede ser útil.

Abrimos el archivo `/etc/suricata/suricata.yaml` para editarlo.
```bash
sudo nano /etc/suricata/suricata.yaml
```

Localizamos la línea `# Community Flow ID` y establecemos el valor de la variable `community-id` en `true`.
```yml
      # Community Flow ID
      # Adds a 'community_id' field to EVE records. These are meant to give
      # records a predictable flow ID that can be used to match records to
      # output of other tools such as Zeek (Bro).
      #
      # Takes a 'seed' that needs to be same across sensors and tools
      # to make the id less predictable.

      # enable/disable the community id feature.
      community-id: true
```

Ahora, los eventos llevarán un ID como `1:S+3BA2UmrHK0Pk+u3XH78GAFTtQ=` que se podrán utilizar para hacer coincidir conjuntos de datos entre distintas herramientas de monitorización.

### 3.3. Añadir interfaz de red
Buscamos la línea `af-packet:` alrededor de la línea número 580. Bajo ella, establecemos el valor y variables de las interfaces que se van a monitorear, en este caso quedará como lo siguiente.
```yml
  - interface: ens19
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
      
  - interface: ens20	
    threads: auto
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes

  - interface: ens21
    threads: auto
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes

  # Put default values here. These will be used for an interface that is not
  # in the list above.
  - interface: default
    #threads: auto
    #use-mmap: no
    #tpacket-v3: yes
```

### 3.4. Añadir proveedores de conjuntos de reglas
Se se quisiera podríamos ampliar las reglas de Suricata añadiendo más proveedores. Podríamos obtener reglas de diversos proveedores gratuitos y comerciales.

Procederíamos a enumerar la lista de proveedores por defecto utilizando el siguiente comando.
```bash
sudo suricata-update list-sources
```

Por ejemplo, si se quiere incluir el conjunto de reglas `et/open`, se puede activar con el siguiente comando.
```bash
sudo suricata-update enable-source et/open
```

Ejecutamos de nuevo el comando `suricata-update` para descargar y actualizar las nuevas reglas. Suricata, por defecto, puede procesar cualquier cambio en las reglas sin reiniciarse.

### 3.5. Configurar reglas personalizadas
En el fichero de configuración de Suricata `/etc/suricata/suricata.yaml` modifico la ruta de las reglas y añado un fichero de reglas personalizado que voy a usar.
```yaml
##
## Configure Suricata to load Suricata-Update managed rules.
##

default-rule-path: /var/lib/suricata/rules

rule-files:
  - custom.rules
```

A continuación, creamos el fichero de reglas personalizadas en la ruta previamente especificada `/var/lib/suricata/rules/custom.rules` con el siguiente contenido.
![Fichero de reglas personalizadas](../vm00-Suricata/custom.rules)

Por último, ejecutamos el comando para validar y cargar las nuevas reglas.

```bash
usuario@vm00:~$ sudo suricata -T -c /etc/suricata/suricata.yaml -v
Notice: suricata: This is Suricata version 7.0.5 RELEASE running in SYSTEM mode
Info: cpu: CPUs/cores online: 2
Info: suricata: Running suricata under test mode
Info: suricata: Setting engine mode to IDS mode by default
Info: exception-policy: master exception-policy set to: auto
Info: logopenfile: fast output device (regular) initialized: fast.log
Info: logopenfile: eve-log output device (regular) initialized: eve.json
Info: logopenfile: stats output device (regular) initialized: stats.log
Info: detect-parse: Rule with ID 500004 is bidirectional, but source and destination are the same, treating the rule as unidirectional
Info: detect: 1 rule files processed. 36 rules successfully loaded, 0 rules failed, 0
Info: threshold-config: Threshold config parsed: 0 rule(s) found
Info: detect: 36 signatures processed. 1 are IP-only rules, 6 are inspecting packet payload, 26 inspect application layer, 0 are decoder event only
Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

### 3.5. Ejecutar Suricata
Ahora que Suricata está instalado y configurado, es el momento de ejecutar la aplicación.
```bash
sudo systemctl start suricata
```

Comprobamos el estado del proceso.
```bash
sudo systemctl status suricata
```

Deberíamos ver la siguiente salida si todo funciona correctamente.
```bash
usuario@vm00:~$ sudo systemctl status suricata
● suricata.service - LSB: Next Generation IDS/IPS
     Loaded: loaded (/etc/init.d/suricata; generated)
     Active: active (running) since Wed 2024-06-12 17:55:36 CEST; 24min ago
       Docs: man:systemd-sysv-generator(8)
    Process: 25490 ExecStart=/etc/init.d/suricata start (code=exited, status=0/SUCCESS)
      Tasks: 12 (limit: 4557)
     Memory: 92.3M
        CPU: 54.432s
     CGroup: /system.slice/suricata.service
             └─25569 /usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid --af-packet -D>

jun 12 17:55:36 vm00 systemd[1]: Starting LSB: Next Generation IDS/IPS...
jun 12 17:55:36 vm00 suricata[25490]: Starting suricata in IDS (af-packet) mode... done.
jun 12 17:55:36 vm00 systemd[1]: Started LSB: Next Generation IDS/IPS.
```

Suricata también registra eventos en el archivo `/var/log/suricata/eve.json` utilizando el formato JSON. Para leer e interpretar esas reglas, necesitaríamos instalar `jq` en ese caso.

## 4. Instalar Filebeat
### 4.1. Descargar e instalar Filebeat
Nos descargamos `Filebeat` con el siguiente comando:
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.2-linux-x86_64.tar.gz
```

Después, lo descomprimimos:
```bash
tar xzvf filebeat-8.13.2-linux-x86_64.tar.gz
```

Eliminamos el fichero comprimido para ahorrar espacio en la máquina.
```bash
rm filebeat-8.13.2-linux-x86_64.tar.gz
```
### 4.2. Configurar Filebeat
El fichero de configuración de Filebeat `filebeat.yml` debería de quedar de la siguiente manera.
![Fichero de configuración filebeat.yml](../vm00-Suricata/filebeat.yml)

También debemos pasarnos el certificado `ca.crt` de `elasticsearch` que está dentro del contendor de `elasticssearch` de docker en la otra máquina.

Para copiar del contenedor de `elasticsearch` al host el `ca.crt` que necesitaremos pasar a la máquina donde estará instalado `Filebeat`.
```bash
docker cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt
```

En la máquina donde está `Filebeat` hay que meterlo en el directorio que se ha especificado en el fichero de configuración `filebeat.yml`, que en este caso es `/home/usuario/filebeat-8.13.2-linux-x86_64/ca.crt`.

### 4.3. Habilitar y configurar modulo de Suricata
Comprobamos que el modulo de `Suricata` este en la lista de módulos disponibles y no habilitados.
```bash
./filebeat modules list
```

Habilito el módulo de `Suricata` con el siguiente comando.
```bash
./filebeat modules enable suricata
```

Dentro de la carpeta de instalación de `Filebeat` editamos el fichero de configuración del módulo de `Filebeat` con la siguiente información `./modules.d/suricata.yml`.
```yaml
# Module: suricata
# Docs: https://www.elastic.co/guide/en/beats/filebeat/8.12/filebeat-module-suricata.html

- module: suricata
  # All logs
  eve:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    var.paths: ["/var/log/suricata/eve.json"]
```

### 4.4. Iniciar Filebeat
Iniciamos filebeat en segundo plano para que empiece a recolectar los logs y enviarlos a `elasticsearch`.
```bash
./filebeat setup &
```
`-e` es opcional y envía la salida al error estándar en lugar de la salida del registro configurado.

Es importante recordar que antes de iniciar Filebeat hay que pasar el certificado que genera Elasticsearch en la máquina VM01 para que el SSL funcione correctamente.
