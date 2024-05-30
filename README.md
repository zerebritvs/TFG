# Implementación de un sistema de alerta temprana de amenazas de seguridad con Suricata, Elasticsearch, Kibana y Elastalert2

¡Bienvenido a este repositorio!

## Descripción

Este repositorio contiene todos los archivos y configuraciones necesarios para la implementación de un sistema de alerta temprana de amenazas de seguridad utilizando las siguientes tecnologías:
- **Suricata:** Sistema de detección de intrusiones basado en red.
- **Elasticsearch:** Motor de búsqueda y análisis distribuido.
- **Kibana:** Herramienta de visualización y análisis de datos.
- **Elastalert2:** Herramienta para la creación de alertas basadas en reglas en Elasticsearch.

El laboratorio está compuesto por cuatro máquinas virtuales que simulan el entorno de prueba:
- `VM00 - Suricata`: Máquina que corre Suricata para la detección de amenazas en la red.
- `VM01 - Elastic server`: Máquina que corre Elasticsearch y Kibana para el almacenamiento y visualización de datos.
- `VM02 - Kali atacante`: Máquina que simula al atacante, utilizando Kali Linux.
- `VM03 - Web server víctima`: Máquina que actúa como servidor web víctima de los ataques.

Dentro de cada carpeta de cada máquina, se encuentra un archivo `.md` que explica cómo instalar y configurar cada componente para que todo el sistema funcione correctamente.

## Instrucciones de uso
Para replicar este laboratorio, sigue los siguientes pasos:

1. **Clona este repositorio:**
```bash
git clone https://github.com/zerebritvs/TFG.git
```

2. **Configuración de las máquinas virtuales:**
Navega a cada carpeta (vm00, vm01, vm02, vm03) y sigue las instrucciones detalladas en los archivos .md correspondientes para configurar cada máquina.

3. **Instalación y configuración de los componentes:**
    - vm00 - Suricata: Sigue las instrucciones para instalar y configurar Suricata.
    - vm01 - Elastic server: Sigue las instrucciones para instalar y configurar Elasticsearch y Kibana.
    - vm02 - Kali atacante: Sigue las instrucciones para preparar el entorno de ataque.
    - vm03 - Web server víctima: Sigue las instrucciones para configurar el servidor web que será atacado.

4. **Ejecución del sistema:**
    1. Inicia todas las máquinas virtuales.
    2. Realiza los ataques desde vm02 - Kali atacante hacia vm03 - Web server víctima.
    3. Monitorea y analiza las alertas generadas por Suricata en vm00 y visualiza los datos en vm01.

## Contribución
¡Tu contribución es bienvenida! Si deseas mejorar este proyecto, por favor sigue estos pasos:

1. Haz un fork de este repositorio.
2. Crea una nueva rama (git checkout -b feature/nueva-funcionalidad).
3. Realiza tus cambios y haz commit (git commit -am 'Añadir nueva funcionalidad').
4. Sube tus cambios a la rama (git push origin feature/nueva-funcionalidad).
5. Abre un Pull Request.

## Conclusión
Este proyecto proporciona una implementación detallada de un sistema de alerta temprana de amenazas de seguridad utilizando tecnologías robustas y modernas. Esperamos que este repositorio te sea útil para entender y aplicar estos conceptos en tus propios proyectos de ciberseguridad.

Para cualquier duda o sugerencia, no dudes en abrir un issue en este repositorio. ¡Gracias por tu interés y colaboración!