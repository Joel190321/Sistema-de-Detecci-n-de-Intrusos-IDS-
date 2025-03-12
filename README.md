## 🔥 Sistema de Detección de Intrusos (IDS) 🔥

Bienvenido a IDS-PyGuard, un potente Sistema de Detección de Intrusos (IDS) desarrollado en Python que analiza el tráfico de red en tiempo real, detecta posibles amenazas y genera alertas de seguridad.

# 🚀 Características Principales

- ✅ Captura de paquetes en tiempo real utilizando Scapy
- ✅ Detección de tráfico sospechoso en TCP, UDP e ICMP
- ✅ Identificación de ataques como escaneos de puertos, brute force y spoofing
- ✅ Almacenamiento de alertas en SQLite
- ✅ Generación automática de un reporte en HTML con gráficos de análisis
- ✅ Implementación de gráficos interactivos con Chart.js
- ✅ Posibilidad de detener la captura cuando se detecta una cantidad crítica de amenazas

# 🛠️ Instalación y Requisitos

- Antes de ejecutar el IDS, asegúrate de tener instalados los siguientes paquetes en tu sistema:

```bash
pip install scapy sqlite3 datetime json
```
---
 
# 📥 Clonar el Repositorio
```bash
git clone https://github.com/tu-usuario/IDS-PyGuard.git
cd IDS-PyGuard
```

# 🎯 Uso

- 1️ python app.py
- 2 Visualizar el Reporte de Alertas

- firefox report.html  # O abre el archivo manualmente

# 📊 Reporte de Seguridad

Cada vez que se detectan amenazas, el IDS genera automáticamente un archivo report.html con gráficos y detalles de las alertas.

- 🔹 Distribución de Severidad (Alta, Media, Baja)
- 🔹 Tipos de Ataques Detectados
- 🔹 Detalles completos de cada alerta

# 🛡️ Tipos de Ataques Detectados

### Tipos de Ataques Detectados

| Tipo de Ataque      | Descripción                                      | Severidad  | Recomendación |
|---------------------|--------------------------------------------------|------------|--------------|
| **Port Scan**      | Escaneo de puertos sospechoso                     | 🔴 Alta    | Bloquear IP y revisar firewall |
| **Brute Force**    | Intentos repetidos de acceso                     | 🔴 Alta    | Implementar 2FA y bloquear IP |
| **DNS Spoofing**   | Tráfico sospechoso en DNS                         | 🟡 Media   | Verificar configuración DNS |
| **Ping Sweep**     | Barrido de red con ICMP                           | 🔵 Baja    | Revisar reglas de firewall |
| **Buffer Overflow**| Paquete de gran tamaño sospechoso                 | 🔴 Alta    | Revisar servicios de red |



# 📜 Licencia

Este proyecto está bajo la Licencia MIT. ¡Siéntete libre de mejorarlo y contribuir! 🚀

# 📧 Contacto: Si tienes alguna pregunta o sugerencia, contáctame en ype0111@gmail.com.

# 💻 Autor: JoelDavid

