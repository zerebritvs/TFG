# VM01 - Elastic server
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
auto ens18
iface ens18 inet dhcp

# RINT - VLAN 798
auto ens19
iface ens19 inet static
      address 10.2.2.1
      netmask 255.255.255.0
```

Reiniciamos el servicio de red para aplicar los cambios realizados.
```bash
sudo systemctl restart networking.service
```

Deberíamos de tener la siguiente configuración de red.
```bash
root@vm01:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:09:48:01 brd ff:ff:ff:ff:ff:ff
    altname enp0s18
    inet 10.0.48.1/18 brd 10.0.63.255 scope global dynamic ens18
       valid_lft 1489sec preferred_lft 1489sec
3: ens19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:98:48:01 brd ff:ff:ff:ff:ff:ff
    altname enp0s19
    inet 10.2.2.1/24 brd 10.2.2.255 scope global ens19
       valid_lft forever preferred_lft forever
```
## 3. Instalar docker y docker-compose
Instalamos docker en la versión `24.0.5`.
```bash
sudo apt install docker.io
```

Comprobamos que la versión de docker es la `24.0.5`.
```bash
root@vm01:~# docker -v
Docker version 24.0.5, build 24.0.5-0ubuntu1~22.04.1
```

Instalamos `docker-compose`.
```bash
sudo apt install docker-compose-v2
```

Verificamos la versión de `docker-compose`, para ver que se instaló correctamente.
```bash
root@vm01:~# docker compose version
Docker Compose version 2.20.2+ds1-0ubuntu1~22.04.1
```

Añadimos al usuario `usuario` al grupo de `docker`, para que este pueda usar docker sin problemas.
Esto se hace modificando esta línea en el fichero de configuración `/etc/group`.
```bash
docker:x:120:usuario
```

Reiniciamos los servicios de docker para evitar conflictos con el siguiente comando.
```bash
sudo systemctl restart docker.service docker.socket
```

## 4. Despliegue de Elasticsearch, Kibana  y Elastalert2 con docker compose
### 4.1. Configuración del fichero docker-compose.yaml
Primero creamos un directorio vacío llamado `elk` con `mkdir elk`.

Creamos el fichero de configuración de variables de entorno para elk `.env`.
```yaml
# Project namespace (defaults to the current folder name if not set)
#COMPOSE_PROJECT_NAME=myproject

# Password for the 'elastic' user (at least 6 characters)
ELASTIC_PASSWORD=elastic123

# Password for the 'kibana_system' user (at least 6 characters)
KIBANA_PASSWORD=kibana123

# Version of Elastic products
STACK_VERSION=8.13.2

# Version of Elastalert2 service
ELASTALERT2_VERSION=2.17.0

# Set the cluster name
CLUSTER_NAME=elk-cluster

# Set the Filebeat bay ip
FILEBEAT_BAY=10.2.2.1

# Set to 'basic' or 'trial' to automatically start the 30-day trial
LICENSE=basic
#LICENSE=trial

# Port to expose Elasticsearch HTTP API to the host
ES_PORT=9200

# Port to expose Kibana to the host
KIBANA_PORT=80

# Increase or decrease based on the available host memory (in bytes)
ES_MEM_LIMIT=4294967296
KB_MEM_LIMIT=2147483648

# SAMPLE Predefined Key only to be used in POC environments
ENCRYPTION_KEY=345d578f69bc0e217333076f441f120bc6bdf37101ae19eb05aac9d3cbe026c1
```

Creamos el archivo `docker-compose.yaml`, que despliega los contenedores de ELK.
```yaml
version: "2"

volumes:
  certs:
    driver: local
    name: certs
  elasticsearchdata:
    driver: local
    name: elasticsearchdata
  kibanadata:
    driver: local
    name: kibanadata

networks:
  default:
    name: elastic
    external: false

services:
  setup:
    container_name: setup
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
    user: "0"
    command: >
      bash -c '
        if [ x${ELASTIC_PASSWORD} == x ]; then
          echo "Set the ELASTIC_PASSWORD environment variable in the .env file";
          exit 1;
        elif [ x${KIBANA_PASSWORD} == x ]; then
          echo "Set the KIBANA_PASSWORD environment variable in the .env file";
          exit 1;
        fi;
        if [ ! -f config/certs/ca.zip ]; then
          echo "Creating CA";
          bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip;
          unzip config/certs/ca.zip -d config/certs;
        fi;
        if [ ! -f config/certs/certs.zip ]; then
          echo "Creating certs";
          echo -ne \
          "instances:\n"\
          "  - name: elasticsearch\n"\
          "    dns:\n"\
          "      - elasticsearch\n"\
          "      - localhost\n"\
          "    ip:\n"\
          "      - 127.0.0.1\n"\
          "      - ${FILEBEAT_BAY}\n"\
          "  - name: kibana\n"\
          "    dns:\n"\
          "      - kibana\n"\
          "      - localhost\n"\
          "    ip:\n"\
          "      - 127.0.0.1\n"\
          > config/certs/instances.yml;
          bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip --in config/certs/instances.yml --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key;
          unzip config/certs/certs.zip -d config/certs;
          cp config/certs/ca/ca.crt config/certs/ca/ca.pem
        fi;
        echo "Setting file permissions"
        chown -R root:root config/certs;
        find . -type d -exec chmod 750 \{\} \;;
        find . -type f -exec chmod 640 \{\} \;;
        echo "Waiting for Elasticsearch availability";
        until curl -s --cacert config/certs/ca/ca.crt https://elasticsearch:9200 | grep -q "missing authentication credentials"; do sleep 30; done;
        echo "Setting kibana_system password";
        until curl -s -X POST --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" https://elasticsearch:9200/_security/user/kibana_system/_password -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do sleep 10; done;
        echo "All done!";
      '
    healthcheck:
      test: ["CMD-SHELL", "[ -f config/certs/elasticsearch/elasticsearch.crt ]"]
      interval: 1s
      timeout: 5s
      retries: 120

  elasticsearch:
    container_name: elasticsearch
    depends_on:
      setup:
        condition: service_healthy
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    labels:
      co.elastic.logs/module: elasticsearch
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - elasticsearchdata:/usr/share/elasticsearch/data
    ports:
      - ${FILEBEAT_BAY}:${ES_PORT}:9200
    environment:
      - node.name=elasticsearch
      - cluster.name=${CLUSTER_NAME}
      - discovery.type=single-node
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.http.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.transport.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=${LICENSE}
    mem_limit: ${ES_MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  kibana:
    container_name: kibana
    depends_on:
      elasticsearch:
        condition: service_healthy
    image: docker.elastic.co/kibana/kibana:${STACK_VERSION}
    labels:
      co.elastic.logs/module: kibana
    volumes:
      - certs:/usr/share/kibana/config/certs
      - kibanadata:/usr/share/kibana/data
    ports:
      - ${KIBANA_PORT}:5601
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
      - XPACK_SECURITY_ENCRYPTIONKEY=${ENCRYPTION_KEY}
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${ENCRYPTION_KEY}
      - XPACK_REPORTING_ENCRYPTIONKEY=${ENCRYPTION_KEY}
    mem_limit: ${KB_MEM_LIMIT}
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s -I http://localhost:5601 | grep -q 'HTTP/1.1 302 Found'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  elastalert2:
    container_name: elastalert2
    depends_on:
      elasticsearch:
        condition: service_healthy
      kibana:
        condition: service_healthy
    image: jertel/elastalert2:${ELASTALERT2_VERSION}
    restart: unless-stopped
    volumes:
      - ./elastalert2/elastalert2.yaml:/opt/elastalert/config.yaml
      - ./elastalert2/rules:/opt/elastalert/rules
      - ./elastalert2/smtp_auth.yaml:/opt/elastalert/smtp_auth.yaml
```

### 4.2. Configuración de Elastalert2
Dentro del directorio creado previamente `~/elk` creamos un directorio para elastalert2 `mkdir elastalert2`.

En este nuevo directorio creamos el fichero de configuración `elastalert2.yaml`.

```yaml
# This is the folder that contains the rule yaml files
# This can also be a list of directories
# Any .yaml file will be loaded as a rule
rules_folder: /opt/elastalert/rules

# How often ElastAlert will query Elasticsearch
# The unit can be anything from weeks to seconds
run_every:
  seconds: 10

# ElastAlert will buffer results from the most recent
# period of time, in case some log sources are not in real time
buffer_time:
  minutes: 1

# The Elasticsearch hostname for metadata writeback
# Note that every rule can have its own Elasticsearch host
es_host: elasticsearch

# The Elasticsearch port
es_port: 9200

# Option basic-auth username and password for Elasticsearch
es_username: elastic
es_password: elastic123

# Connect with TLS to Elasticsearch
use_ssl: False

# Verify TLS certificates
verify_certs: False
  #ca_certs: /opt/elastalert/ca.crt

# The index on es_host which is used for metadata storage
# This can be a unmapped index, but it is recommended that you run
# elastalert-create-index to set a mapping
writeback_index: elastalert_status
writeback_alias: elastalert_alerts

# If an alert fails for some reason, ElastAlert will retry
# sending the alert until this time period has elapsed
alert_time_limit:
  days: 2
```

Además creo el fichero `smtp_auth.yaml` donde están las credenciales para conectarme al servidor de `SMTP`.
```yaml
user: user@gmail.com
password: apppassword
```

Después creamos otra carpeta dentro de `~/elk/elastalert2` para almacenar las reglas de elastalert2 `mkdir rules`.

Dentro de la carpeta `~/elk/elastalert2/rules` creo el fichero que define una regla para elastalert2 llamado `suricata_alert_rule.yaml`.
```yaml
name: Suricata Alert
index: ".ds-filebeat-*"
type: any

realert:
    seconds: 0

filter:
- term:
    suricata.eve.alert.signature_id : "2100498"

alert:
- "email"

email:
- "email@gmail.com"

smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_ssl: false
from_addr: "email@gmail.com"
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"

email_format: "html"
alert_subject: "SURICATA ALERT"
alert_text_type: alert_text_only
alert_text_args:
- "@timestamp"
- "suricata.eve.alert.signature"
- "suricata.eve.alert.signature_id"
- "suricata.eve.alert.category"
alert_text: "<h2>¡Alerta de Suricata!</h2>
    <p>Se ha detectado una alerta de Suricata en el sistema.</p>
    <p>La información de la alerta es la siguiente:</p>
    <ul>
        <li>Timestamp: {0}</li>
        <li>Rule name: {1}</li>
        <li>Rule ID: {2}</li>
        <li>Category: {3}</li>
    </ul>
    <p>Consulta los registros desde kibana obtener más información</p>
    "
```

Para que los contenedores se desplieguen tal y como viene definido en el archivo `docker-compose.yml` ejecutamos el siguiente comando.
```bash
sudo docker-compose up -d
```

Como se puede apreciar tras el despliegue los contenedores están corriendo satisfactoriamente.
```bash
root@vm01:/home/usuario/elk# docker ps -a
CONTAINER ID   IMAGE                                                  COMMAND                  CREATED              STATUS                        PORTS                              NAMES
bfa28b64b8f5   jertel/elastalert2:2.17.0                              "/opt/elastalert/run…"   About a minute ago   Up 23 seconds                                                    elastalert2
5b98c5f870d5   docker.elastic.co/kibana/kibana:8.13.2                 "/bin/tini -- /usr/l…"   About a minute ago   Up About a minute (healthy)   0.0.0.0:5601->5601/tcp             kibana
25b53c77f2a4   docker.elastic.co/elasticsearch/elasticsearch:8.13.2   "/bin/tini -- /usr/l…"   About a minute ago   Up About a minute (healthy)   0.0.0.0:9200->9200/tcp, 9300/tcp   elasticsearch
922c67ee3f60   docker.elastic.co/elasticsearch/elasticsearch:8.13.2   "/bin/tini -- /usr/l…"   About a minute ago   Exited (0) 59 seconds ago                                        setup
```

Si accedemos a la página de `kibana` nos aparece un panel de inicio de sesión, donde se introducirán las credenciales de elastic.
![Kibana Login](https://github.com/zerebritvs/TFG/tree/main/images/elasticLogin.png)

Una vez introducidas las credenciales de elastic podemos observar que estamos dentro de kibana y todo funciona correctamente.
![Kibana Home](https://github.com/zerebritvs/TFG/tree/main/images/elasticHome.png)

Para configurar la contraseña de GMAIL para SMTP para que funcione sin problemas elastalert2 es necesario añadir una `App password`.
![App password GMAIL](https://github.com/zerebritvs/TFG/tree/main/images/appPassword.png)

Para copiar del contenedor de elasticsearch al host el `ca.crt` que necesitaremos pasar a la máquina donde estará instalado `Filebeat`.
```bash
docker cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt
```

Para limpiar los logs de docker de un contenedor específico:
```bash
: > $(docker inspect --format='{{.LogPath}}' <container_name_or_id>)
```