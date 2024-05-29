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

# RINT - VLAN 798 - Red interna
auto ens19
iface ens19 inet static
      address 10.2.2.80
      netmask 255.255.255.0
      up ip link set ens19 promisc on

# RLAB2 - VLAN709 - IP Lab27 por DHCP (VALEN, OJO)
auto ens20
iface ens20 inet dhcp
      up ip link set ens20 promisc on

# RLAB3 - VLAN 799 -- LAB27 INTERNA (VALEN, OJO)
auto ens21
iface ens21 inet static
      address 10.2.1.80
      netmask 255.255.255.0
      up ip link set ens21 promisc on
```

Reiniciamos el servicio de red para aplicar los cambios realizados.
```bash
sudo systemctl restart networking.service
```

En el fichero `/etc/sysctl.conf` descomentamos la siguiente línea para habilitar el renvío de paquetes.
```
# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1
```

Aplicamos los cambios realizados para el enrutamiento de paquetes IPV4.
```bash
sudo sysctl -p
```

Deberíamos de tener la siguiente configuración de red.
```bash
root@vm00:/var/log/suricata# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s18
    inet 10.0.48.250/18 brd 10.0.63.255 scope global dynamic ens18
       valid_lft 1799sec preferred_lft 1799sec
3: ens19: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:98:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s19
    inet 10.2.2.80/24 brd 10.2.2.255 scope global ens19
       valid_lft forever preferred_lft forever
4: ens20: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:27:80 brd ff:ff:ff:ff:ff:ff
    altname enp0s20
    inet 10.0.27.80/18 brd 10.0.63.255 scope global dynamic ens20
       valid_lft 1799sec preferred_lft 1799sec
5: ens21: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:99:48:00 brd ff:ff:ff:ff:ff:ff
    altname enp0s21
    inet 10.2.1.80/24 brd 10.2.1.255 scope global ens21
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

Habilitamos el servicio Suricata.
```bash
sudo systemctl enable suricata
```

Antes de continuar, detenemos el servicio Suricata, ya que primero tenemos que configurarlo.
```bash
sudo systemctl stop suricata
```

Suricata almacena su configuración en el archivo `/etc/suricata/suricata.yaml`. El modo por defecto de Suricata es el Modo IDS (Sistema de Detección de Intrusos), en el que sólo se registra el tráfico y no se detiene. Si eres nuevo en Suricata, deberías dejar el modo sin cambios. Una vez que lo hayas configurado y hayas aprendido más, puedes activar el modo IPS (Sistema de Prevención de Intrusiones).

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
Podemos ampliar las reglas de Suricata añadiendo más proveedores. Podemos obtener reglas de diversos proveedores gratuitos y comerciales.

Procedemos a enumerar la lista de proveedores por defecto utilizando el siguiente comando.
```bash
sudo suricata-update list-sources
```

Por ejemplo, si quieres incluir el conjunto de reglas `et/open`, puedes activarlo con el siguiente comando.
```bash
sudo suricata-update enable-source et/open
```

Ejecutamos de nuevo el comando `suricata-update` para descargar y actualizar las nuevas reglas. Suricata, por defecto, puede procesar cualquier cambio en las reglas sin reiniciarse.

### 3.5. Validar la configuración de Suricata
Suricata incluye una herramienta de validación para comprobar si hay errores en el archivo de configuración y en las reglas. Ejecutamos el siguiente comando para ejecutar la herramienta de validación.
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
25/2/2023 -- 06:51:11 - <Info> - Running suricata under test mode
25/2/2023 -- 06:51:11 - <Notice> - This is Suricata version 6.0.10 RELEASE running in SYSTEM mode
25/2/2023 -- 06:51:11 - <Info> - CPUs/cores online: 2
25/2/2023 -- 06:51:11 - <Info> - fast output device (regular) initialized: fast.log
25/2/2023 -- 06:51:11 - <Info> - eve-log output device (regular) initialized: eve.json
25/2/2023 -- 06:51:11 - <Info> - stats output device (regular) initialized: stats.log
25/2/2023 -- 06:51:22 - <Info> - 1 rule files processed. 33519 rules successfully loaded, 0 rules failed
25/2/2023 -- 06:51:22 - <Info> - Threshold config parsed: 0 rule(s) found
25/2/2023 -- 06:51:22 - <Info> - 33522 signatures processed. 1189 are IP-only rules, 5315 are inspecting packet payload, 26814 inspect application layer, 108 are decoder event only
25/2/2023 -- 06:51:34 - <Notice> - Configuration provided was successfully loaded. Exiting.
25/2/2023 -- 06:51:34 - <Info> - cleaning up signature grouping structure... complete
```

La bandera `-T` indica a Suricata que se ejecute en modo de prueba, la bandera `-c` configura la ubicación del archivo de configuración y la bandera `-v` imprime la salida detallada del comando. Dependiendo de la configuración de tu sistema y del número de reglas añadidas, el comando puede tardar unos minutos en finalizar.

### 3.6. Ejecutar Suricata
Ahora que Suricata está configurado e instalado, es el momento de ejecutar la aplicación.
```bash
sudo systemctl start suricata
```

Comprobamos el estado del proceso.
```bash
sudo systemctl status suricata
```

Deberíamos ver la siguiente salida si todo funciona correctamente.
```bash
root@vm00:/var/lib/suricata/rules# systemctl status suricata
● suricata.service - LSB: Next Generation IDS/IPS
     Loaded: loaded (/etc/init.d/suricata; generated)
     Active: active (running) since Sun 2024-05-19 16:16:49 CEST; 39min ago
       Docs: man:systemd-sysv-generator(8)
    Process: 97375 ExecStart=/etc/init.d/suricata start (code=exited, status=0/SUCCESS)
      Tasks: 12 (limit: 4558)
     Memory: 61.1M
        CPU: 28.263s
     CGroup: /system.slice/suricata.service
             └─97384 /usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/su>

may 19 16:16:49 vm00 systemd[1]: Starting LSB: Next Generation IDS/IPS...
may 19 16:16:49 vm00 suricata[97375]: Starting suricata in IDS (af-packet) mode... done.
may 19 16:16:49 vm00 systemd[1]: Started LSB: Next Generation IDS/IPS.
```

El proceso puede tardar unos minutos en terminar de analizar todas las reglas. Por lo tanto, la comprobación de estado anterior no es una indicación completa de si Suricata está funcionando y listo. Para ello, se puede controlar el archivo de registro mediante el siguiente comando.
```bash
sudo tail -f /var/log/suricata/suricata.log
```

### 3.7. Probar reglas de Suricata
Comprobaremos si Suricata detecta algún tráfico sospechoso. La guía de Suricata recomienda probar la regla ET Open número **2100498** utilizando el siguiente comando.
```bash
curl http://testmynids.org/uid/index.html
```

Obtendremos la siguiente respuesta.
```bash
uid=0(root) gid=0(root) groups=0(root)
```

El comando anterior simula devolver la salida del comando `id` que se puede ejecutar en un sistema comprometido. Para comprobar si Suricata detectó el tráfico, debemos comprobar el archivo de registro utilizando el número de regla especificado.
```bash
grep 2100498 /var/log/suricata/fast.log
```

Si la solicitud utilizó IPv4, deberíamos ver la siguiente salida.
```bash
02/19/2023-10:13:17.872335  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 108.158.221.5:80 -> 95.179.185.42:36364
```

Suricata también registra eventos en el archivo `/var/log/suricata/eve.json` utilizando el formato JSON. Para leer e interpretar esas reglas, necesitaríamos instalar `jq` en ese caso.

### 3.8. Configurar reglas personalizadas
En el fichero de configuración de Suricata `/etc/suricata/suricata.yaml` modifico la ruta de las reglas y añado un fichero de reglas personalizado que voy a usar.
```yaml
##
## Configure Suricata to load Suricata-Update managed rules.
##

default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - custom.rules
```

A continuación, creamos el fichero de reglas en la ruta previamente especificada `/var/lib/suricata/rules/custom.rules` con el siguiente contenido.
```bash
# SQL Injection (SQLI) Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, DELETE FROM in URI"; flow:established,to_server; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; classtype:web-application-attack; sid:300001; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, INSERT INTO in URI"; flow:established,to_server; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; classtype:web-application-attack; sid:300002; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SELECT FROM in URI"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"FROM"; nocase; http_uri; pcre:"/SELECT\b.*FROM/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; classtype:web-application-attack; sid:300003; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, UNION SELECT in URI"; flow:established,to_server; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; classtype:web-application-attack; sid:300004; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, UPDATE SET in URI"; flow:established,to_server; content:"UPDATE"; nocase; http_uri; content:"SET"; nocase; distance:0; http_uri; pcre:"/\WUPDATE\s+[A-Za-z0-9$_].*?\WSET\s+[A-Za-z0-9$_].*?\x3d/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; classtype:web-application-attack; sid:300005; rev:1;)

alert http any any -> $HOME_NET $HTTP_PORTS (msg:"Possible SQL Injection Attempt, varchar( in URI"; flow:established,to_server; uricontent:"varchar("; nocase; classtype:web-application-attack; sid:300006; rev:5;)

alert http any any -> $HOME_NET $HTTP_PORTS (msg:"Possible SQL Injection Attempt, exec( in URI"; flow:established,to_server; uricontent:"exec("; nocase; classtype:web-application-attack; sid:300007; rev:1;)

alert http any any -> $HOME_NET $HTTP_PORTS (msg:"Possible SQL Injection Attempt Danmec related (declare)"; flow:established,to_server; uricontent:"DECLARE "; nocase; uricontent:"CHAR("; nocase; uricontent:"CAST("; nocase; classtype:web-application-attack; sid:300008; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection INTO OUTFILE Arbitrary File Write Attempt"; flow:established,to_server; content:"INTO"; http_uri; nocase; content:"OUTFILE"; nocase; http_uri; pcre:"/INTO.+OUTFILE/Ui"; reference:url,www.milw0rm.com/papers/372; reference:url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection; reference:url,websec.wordpress.com/2007/11/17/mysql-into-outfile/; classtype:web-application-attack; sid:300009; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, ALTER in URI"; flow:to_server,established; uricontent:"ALTER"; nocase; pcre:"/ALTER\ +(database|procedure|table|column)/Ui"; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,www.w3schools.com/SQl/sql_alter.asp; classtype:web-application-attack; sid:300010; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, DROP in URI"; flow:to_server,established; uricontent:"DROP"; nocase; pcre:"/DROP\ +(database|procedure|table|column)/Ui"; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,www.w3schools.com/SQl/sql_drop.asp; classtype:web-application-attack; sid:300011; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, CREATE in URI"; flow:to_server,established; uricontent:"CREATE"; nocase; pcre:"/CREATE\ +(database|procedure|table|column|directory)/Ui"; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,www.w3schools.com/Sql/sql_create_db.asp; classtype:web-application-attack; sid:300012; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Blind SQL Injection Attempt, SELECT SUBSTR/ING in URI"; flow:established,to_server; uricontent:"SELECT"; nocase; uricontent:"SUBSTR"; nocase; pcre:"/SELECT.+SUBSTR/Ui"; reference:url,www.1keydata.com/sql/sql-substring.html; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,msdn.microsoft.com/en-us/library/ms161953.aspx; classtype:web-application-attack; sid:300013; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SHOW CHARACTER SET in URI"; flow:established,to_server; uricontent:"SHOW"; nocase; uricontent:"CHARACTER"; nocase; content:"SET"; nocase; pcre:"/SHOW.+CHARACTER.+SET/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/5.0/en/show-character-set.html; classtype:web-application-attack; sid:300014; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SHOW VARIABLES in URI"; flow:established,to_server; uricontent:"SHOW"; nocase; uricontent:"VARIABLES"; nocase; pcre:"/SHOW.+VARIABLES/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/5.1/en/server-system-variables.html; classtype:web-application-attack; sid:300015; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SHOW CURDATE/CURTIME in URI"; flow:established,to_server; uricontent:"SHOW"; nocase; uricontent:"CUR"; nocase; pcre:"/SHOW.+CUR(DATE|TIME)/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_curdate; reference:url,dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_curtime; classtype:web-application-attack; sid:300016; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SHOW TABLES in URI"; flow:established,to_server; uricontent:"SHOW"; nocase; uricontent:"TABLES"; nocase; pcre:"/SHOW.+TABLES/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/4.1/en/show-tables.html; classtype:web-application-attack; sid:300017; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, BULK INSERT in URI to Insert File Content into Database Table"; flow:established,to_server; content:"BULK"; nocase; http_uri; content:"INSERT"; nocase; http_uri; distance:0; reference:url,msdn.microsoft.com/en-us/library/ms188365.aspx; reference:url,msdn.microsoft.com/en-us/library/ms175915.aspx; reference:url,www.sqlteam.com/article/using-bulk-insert-to-load-a-text-file; classtype:web-application-attack; sid:300018; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SELECT VERSION in URI"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"VERSION"; nocase; distance:1; http_uri; reference:url,support.microsoft.com/kb/321185; classtype:web-application-attack; sid:300019; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, INSERT VALUES in URI"; flow:established,to_server; uricontent:"INSERT"; nocase; uricontent:"VALUES"; nocase; pcre:"/INSERT.+VALUES/Ui"; reference:url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/; reference:url,en.wikipedia.org/wiki/Insert_(SQL); classtype:web-application-attack; sid:300020; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL Injection Attempt, SELECT CONCAT in URI"; flow:established,to_server; uricontent:"SELECT"; nocase; uricontent:"CONCAT"; nocase; pcre:"/SELECT.+CONCAT/Ui"; reference:url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/; reference:url,www.webdevelopersnotes.com/tutorials/sql/a_little_more_on_the_mysql_select_statement.php3; classtype:web-application-attack; sid:300021; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible SQL injection Attempt, obfuscated via REVERSE function in URI"; flow:established,to_server; uricontent:"REVERSE"; nocase; pcre:"/[^\w]REVERSE[^\w]?\(/Ui"; reference:url,snosoft.blogspot.com/2010/05/reversenoitcejni-lqs-dnilb-bank-hacking.html; classtype:web-application-attack; sid:300022; rev:1;)

# Local File Inclusion (LFI) Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt, ../ in URI"; flow:to_server,established; uricontent:"../"; classtype:web-application-attack; sid:300101; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt, ....// in URI"; flow:to_server,established; uricontent:"....//"; classtype:web-application-attack; sid:300102; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt, /etc/passwd in URI"; flow:to_server,established; uricontent:"/etc/passwd"; nocase; classtype:web-application-attack; sid:300103; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt, /proc/version in URI"; flow:to_server,established; uricontent:"/proc/version"; nocase; classtype:web-application-attack; sid:300104; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt file:// in URI"; flow:to_server,established; uricontent:"file://"; nocase; classtype:web-application-attack; sid:300105; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt ..%2f in URI"; flow:to_server,established; uricontent:"..%2f"; nocase; classtype:web-application-attack; sid:300106; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt ..%252f in URI"; flow:to_server,established; uricontent:"..%252f"; nocase; classtype:web-application-attack; sid:300107; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt .. in URI"; flow:to_server,established; uricontent:".."; classtype:web-application-attack; sid:300108; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt %2e%2e/ in URI"; flow:to_server,established; uricontent:"%2e%2e/"; nocase; classtype:web-application-attack; sid:300109; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt ..%c0%af in URI"; flow:to_server,established; uricontent:"..%c0%af"; nocase; classtype:web-application-attack; sid:300110; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt %2e%2e%2f in URI"; flow:to_server,established; uricontent:"%2e%2e%2f"; nocase; classtype:web-application-attack; sid:300111; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt %252e%252e%252f in URI"; flow:to_server,established; uricontent:"%252e%252e%252f"; nocase; classtype:web-application-attack; sid:300112; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Local File Inclusion Attempt Null Byte in URI"; flow:to_server,established; uricontent:"%00"; classtype:web-application-attack; sid:300113; rev:1;)

# Remote File Inclusion (RFI) Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, =http:// in URI"; flow:to_server,established; uricontent:"=http://"; nocase; classtype:web-application-attack; sid:300201; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, =https:// in URI"; flow:to_server,established; uricontent:"=https://"; nocase; classtype:web-application-attack; sid:300202; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, include( in URI"; flow:to_server,established; uricontent:"include("; nocase; classtype:web-application-attack; sid:300203; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, PHP Wrapper in URI"; flow:to_server,established; uricontent:"php://"; nocase; classtype:web-application-attack; sid:300204; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, Remote Server IP in URI"; flow:to_server,established; uricontent:"//"; uricontent:"[0-9]"; classtype:web-application-attack; sid:300205; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, Common Remote File Extensions in URI"; flow:to_server,established; uricontent:".php"; uricontent:".asp"; uricontent:".aspx"; uricontent:".jsp"; nocase; classtype:web-application-attack; sid:300206; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Remote File Inclusion Attempt, Base64 Encoded Data in URI"; flow:to_server,established; uricontent:"data:text/plain\;base64,"; nocase; classtype:web-application-attack; sid:300207; rev:2;)

# Command Injection (CI) Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Command Injection Attempt, using \;"; flow:to_server,established; uricontent:"\;"; classtype:web-application-attack; sid:300301; rev:2;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Command Injection Attempt, using &&"; flow:to_server,established; uricontent:"&&"; classtype:web-application-attack; sid:300302; rev:2;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Command Injection Attempt, using ||"; flow:to_server,established; uricontent:"||"; classtype:web-application-attack; sid:300303; rev:2;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Command Injection Attempt, using $()"; flow:to_server,established; uricontent:"$()"; classtype:web-application-attack; sid:300304; rev:2;)

# Brute force Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Brute Force Login Attempt, 5 logins in 60 seconds"; flow:to_server,established; content:"Login"; http_uri; threshold:type limit, track by_src, count 5, seconds 60; classtype:web-application-attack; sid:300401; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Brute Force Login Attempt, Multiple Failed Attempts"; flow:to_server,established; content:"POST"; http_method; content:"/login"; http_uri; content:"HTTP/"; http_header; threshold: type threshold, track by_src, count 5, seconds 60;  classtype:web-application-attack; sid:300402; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Brute Force Login Attempt, Common Usernames"; flow:to_server,established; content:"POST"; http_method; content:"/login"; http_uri; content:"HTTP/"; http_header; pcre:"/(username=)(administrator|root|user|test)/Ui"; classtype:web-application-attack; sid:300403; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Brute Force Login Attempt, Common Passwords"; flow:to_server,established; content:"POST"; http_method; content:"/login"; http_uri; content:"HTTP/"; http_header; pcre:"/(password=)(password123|123456|admin123|qwerty)/Ui"; classtype:web-application-attack; sid:300404; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible Brute Force Login Attempt, Common Credentials"; flow:to_server,established; content:"POST"; http_method; content:"/login"; http_uri; content:"HTTP/"; http_header; pcre:"/(username=)(administrator|root|user|test)&(password=)(password123|123456|admin123|qwerty)/Ui"; classtype:web-application-attack; sid:300405; rev:1;)

# Denial of Service (DoS) and Distributed Denial of Services (DDoS) Rules
alert http any any -> $HTTP_SERVERS any (msg:"Possible HTTP GET Flood Attack"; flow:to_server; content:"GET"; http_method; threshold: type threshold, track by_src, count 50, seconds 10; classtype:denial-of-service; sid:300501; rev:1;)

alert http any any -> $HTTP_SERVERS any (msg:"Possible HTTP POST Flood Attack"; flow:to_server; content:"POST"; http_method; threshold: type threshold, track by_src, count 50, seconds 10; classtype:denial-of-service; sid:300502; rev:1;)

alert http any any -> $HTTP_SERVERS any (msg:"Possible HTTP HEAD Flood Attack"; flow:to_server; content:"HEAD"; http_method; threshold: type threshold, track by_src, count 50, seconds 10; classtype:denial-of-service; sid:300503; rev:1;)

#alert http any any -> $HTTP_SERVERS any (msg:"Possible Large HTTP Request Flood Attack"; flow:to_server; content_length: > 100000; threshold: type threshold, track by_src, count 10, seconds 5; classtype:denial-of-service; sid:300504; rev:1;)

alert tcp any any -> $HTTP_SERVERS any (msg:"Possible SYN Flood Attack"; flags:S; threshold: type threshold, track by_src, count 50, seconds 10; classtype:denial-of-service; sid:300505; rev:1;)

alert udp any any -> $HTTP_SERVERS any (msg:"Possible UDP Flood Attack"; threshold: type threshold, track by_src, count 50, seconds 10; classtype:denial-of-service; sid:300506; rev:1;)

# Cross-Site Scripting (XSS) Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible XSS Attack, script tag"; flow:to_server,established; content:"<script>"; http_client_body; classtype:web-application-attack; sid:300601; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible XSS Attack, alert function"; flow:to_server,established; content:"alert("; http_client_body; classtype:web-application-attack; sid:300602; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible XSS Attack, document.write function"; flow:to_server,established; content:"document.write("; http_client_body; classtype:web-application-attack; sid:300603; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible XSS Attack, onmouseover event"; flow:to_server,established; content:"onmouseover"; http_client_body; classtype:web-application-attack; sid:300604; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible XSS Attack, onerror event"; flow:to_server,established; content:"onerror"; http_client_body; classtype:web-application-attack; sid:300605; rev:1;)

alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Possible XSS Attack, onload event"; flow:to_server,established; content:"onload"; http_client_body; classtype:web-application-attack; sid:300606; rev:1;)
```

Por último, ejecutamos el comando para validar y cargar las nuevas reglas.
```bash
root@vm00:/var/lib/suricata/rules# suricata -T -c /etc/suricata/suricata.yaml -v
Notice: suricata: This is Suricata version 7.0.5 RELEASE running in SYSTEM mode
Info: cpu: CPUs/cores online: 2
Info: suricata: Running suricata under test mode
Info: suricata: Setting engine mode to IDS mode by default
Info: exception-policy: master exception-policy set to: auto
Info: logopenfile: fast output device (regular) initialized: fast.log
Info: logopenfile: eve-log output device (regular) initialized: eve.json
Info: logopenfile: stats output device (regular) initialized: stats.log
Info: detect: 2 rule files processed. 37548 rules successfully loaded, 0 rules failed, 0
Info: threshold-config: Threshold config parsed: 0 rule(s) found
Info: detect: 37551 signatures processed. 1114 are IP-only rules, 4873 are inspecting packet payload, 31350 inspect application layer, 108 are decoder event only
Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

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
```yaml
###################### Filebeat Configuration Example #########################

# This file is an example configuration file highlighting only the most common
# options. The filebeat.reference.yml file from the same directory contains all the
# supported options with more comments. You can use it as a reference.
#
# You can find the full configuration reference here:
# https://www.elastic.co/guide/en/beats/filebeat/index.html

# For more available modules and options, please see the filebeat.reference.yml sample
# configuration file.

# ============================== Filebeat inputs ===============================

filebeat.inputs:

# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input-specific configurations.

# filestream is an input for collecting log messages from files.
- type: filestream

  # Unique ID among all inputs, an ID is required.
  id: my-filestream-id

  # Change to true to enable this input configuration.
  enabled: false

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    - /var/log/*.log
    #- c:\programdata\elasticsearch\logs\*

  # Exclude lines. A list of regular expressions to match. It drops the lines that are
  # matching any regular expression from the list.
  # Line filtering happens after the parsers pipeline. If you would like to filter lines
  # before parsers, use include_message parser.
  #exclude_lines: ['^DBG']

  # Include lines. A list of regular expressions to match. It exports the lines that are
  # matching any regular expression from the list.
  # Line filtering happens after the parsers pipeline. If you would like to filter lines
  # before parsers, use include_message parser.
  #include_lines: ['^ERR', '^WARN']

  # Exclude files. A list of regular expressions to match. Filebeat drops the files that
  # are matching any regular expression from the list. By default, no files are dropped.
  #prospector.scanner.exclude_files: ['.gz$']

  # Optional additional fields. These fields can be freely picked
  # to add additional information to the crawled log files for filtering
  #fields:
  #  level: debug
  #  review: 1

# ============================== Filebeat modules ==============================

filebeat.config.modules:
  # Glob pattern for configuration loading
  path: ${path.config}/modules.d/*.yml

  # Set to true to enable config reloading
  reload.enabled: false

  # Period on which files under path should be checked for changes
  #reload.period: 10s

# ======================= Elasticsearch template setting =======================
setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false
# ================================== General ===================================

# The name of the shipper that publishes the network data. It can be used to group
# all the transactions sent by a single shipper in the web interface.
#name:

# The tags of the shipper are included in their field with each
# transaction published.
#tags: ["service-X", "web-tier"]

# Optional fields that you can specify to add additional information to the
# output.
#fields:
#  env: staging

# ================================= Dashboards =================================
# These settings control loading the sample dashboards to the Kibana index. Loading
# the dashboards is disabled by default and can be enabled either by setting the
# options here or by using the `setup` command.
setup.dashboards.enabled: true
# The URL from where to download the dashboard archive. By default, this URL
# has a value that is computed based on the Beat name and version. For released
# versions, this URL points to the dashboard archive on the artifacts.elastic.co
# website.
#setup.dashboards.url:

# =================================== Kibana ===================================

# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  host: "http://192.168.1.22:5601"
  username: "elastic"
  password: "elastic123"

  # Kibana Space ID
  # ID of the Kibana Space into which the dashboards should be loaded. By default,
  # the Default Space will be used.
  #space.id:

# =============================== Elastic Cloud ================================

# These settings simplify using Filebeat with the Elastic Cloud (https://cloud.elastic.co/).

# The cloud.id setting overwrites the `output.elasticsearch.hosts` and
# `setup.kibana.host` options.
# You can find the `cloud.id` in the Elastic Cloud web UI.
#cloud.id:

# The cloud.auth setting overwrites the `output.elasticsearch.username` and
# `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
#cloud.auth:

# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.

# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["192.168.1.22:9200"]
  #index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
  # Performance preset - one of "balanced", "throughput", "scale",
  # "latency", or "custom".
  #preset: balanced

  # Protocol - either `http` (default) or `https`.
  protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  username: "elastic"
  password: "elastic123"

  ssl.enabled: true
  ssl.certificate_authorities: ["/home/usuario/filebeat-8.13.2-linux-x86_64/ca.crt"]

# ------------------------------ Logstash Output -------------------------------
#output.logstash:
  # The Logstash hosts
  #hosts: ["192.168.1.22:5044"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"

# ================================= Processors =================================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~

# ================================== Logging ===================================

# Sets log level. The default log level is info.
# Available log levels are: error, warning, info, debug
#logging.level: debug

# At debug level, you can selectively enable logging only for some components.
# To enable all selectors, use ["*"]. Examples of other selectors are "beat",
# "publisher", "service".
#logging.selectors: ["*"]

# ============================= X-Pack Monitoring ==============================
# Filebeat can export internal metrics to a central Elasticsearch monitoring
# cluster.  This requires xpack monitoring to be enabled in Elasticsearch.  The
# reporting is disabled by default.

# Set to true to enable the monitoring reporter.
#monitoring.enabled: false

# Sets the UUID of the Elasticsearch cluster under which monitoring data for this
# Filebeat instance will appear in the Stack Monitoring UI. If output.elasticsearch
# is enabled, the UUID is derived from the Elasticsearch cluster referenced by output.elasticsearch.
#monitoring.cluster_uuid:

# Uncomment to send the metrics to Elasticsearch. Most settings from the
# Elasticsearch outputs are accepted here as well.
# Note that the settings should point to your Elasticsearch *monitoring* cluster.
# Any setting that is not set is automatically inherited from the Elasticsearch
# output configuration, so if you have the Elasticsearch output configured such
# that it is pointing to your Elasticsearch monitoring cluster, you can simply
# uncomment the following line.
#monitoring.elasticsearch:

# ============================== Instrumentation ===============================

# Instrumentation support for the filebeat.
#instrumentation:
    # Set to true to enable instrumentation of filebeat.
    #enabled: false

    # Environment in which filebeat is running on (eg: staging, production, etc.)
    #environment: ""

    # APM Server hosts to report instrumentation results to.
    #hosts:
    #  - http://localhost:8200

    # API Key for the APM Server(s).
    # If api_key is set then secret_token will be ignored.
    #api_key:

    # Secret token for the APM Server(s).
    #secret_token:


# ================================= Migration ==================================

# This allows to enable 6.7 migration aliases
#migration.6_to_7.enabled: true
```

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
