# Ciber Analysis MCP Server

> 🔐 MCP Server para análisis de ciberseguridad e inteligencia de redes usando Shodan, nmap, geolocalización IP, DNS lookup, análisis de reputación y WHOIS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-1.16.0+-green.svg)](https://modelcontextprotocol.io/)

## 🚀 Características

- **🔍 Port Scanning**: Escaneo de puertos en tiempo real con nmap (detección de servicios y versiones)
- **🌍 Geolocalización IP**: Ubicación geográfica, ISP, ASN de cualquier dirección IP
- **🛡️ Análisis de Reputación**: Verificación de IPs maliciosas usando AbuseIPDB
- **📡 DNS Lookup**: Resolución completa de registros DNS (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR)
- **📋 WHOIS**: Información de propietarios, registradores y fechas de registro
- **🔐 Shodan Integration**: Acceso a datos históricos de Shodan
- **🔧 Utilidades**: Obtención de IP pública, validaciones, etc.

## 📦 Instalación

### Requisitos Previos

- Python 3.10 o superior
- `uv` package manager (recomendado)
- `nmap` instalado para escaneo de puertos

```bash
# Instalar uv (si no lo tienes)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Instalar nmap
sudo apt install nmap  # Debian/Ubuntu
brew install nmap      # macOS
```

### Opción 1: Instalar desde GitHub

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/ciber-analysis-mcp-server.git
cd ciber-analysis-mcp-server

# Crear entorno virtual e instalar dependencias
uv venv
source .venv/bin/activate  # Linux/Mac
# o .venv\Scripts\activate  # Windows

uv pip install -e .
```

### Opción 2: Instalar directamente con pip

```bash
pip install git+https://github.com/tu-usuario/ciber-analysis-mcp-server.git
```

## 🔧 Configuración

### Variables de Entorno (Opcionales)

```bash
export SHODAN_API_KEY="tu_api_key_aqui"         # Para get_host_info
export ABUSEIPDB_API_KEY="tu_api_key_aqui"     # Para check_ip_reputation
```

**Obtener API Keys gratuitas:**
- Shodan: https://account.shodan.io/
- AbuseIPDB: https://www.abuseipdb.com/register (1000 checks/día gratis)

### Ejecutar el Servidor

#### Modo SSE (Server-Sent Events)

```bash
python ciber-analisys-mcp-server.py
# Servidor escuchando en http://localhost:8003/sse
```

El servidor iniciará en modo SSE por defecto en el puerto 8003.

## 🐳 Uso con Docker Compose

### Con maarifa-wrapper (para pasar variables desde el agente)

```yaml
services:
  ciber_analysis_mcp:
    networks:
      - agents_network
    image: jdelacasa/ubuntu-dind:v2
    privileged: true
    ports:
      - "12005:8080"
    volumes:
      - ./maarifa-wrapper.py:/opt/maarifa-wrapper.py
    environment:
      - SHODAN_API_KEY=${SHODAN_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
    command:
      - /bin/bash
      - -l
      - -c
      - |
        export NVM_DIR="/root/.nvm"
        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

        # Instalar nmap y dependencias
        apt-get update && apt-get install -y nmap
        pip install --break-system-packages mcp-proxy mcp fastapi httpx uvicorn starlette dnspython python-whois

        # Clonar e instalar desde GitHub
        git clone https://github.com/tu-usuario/ciber-analysis-mcp-server.git /opt/ciber_mcp

        # Ejecutar con wrapper
        python3 /opt/maarifa-wrapper.py \
          --host 0.0.0.0 \
          --port 8080 \
          --log-level DEBUG \
          python3 /opt/ciber_mcp/ciber-analisys-mcp-server.py
```

### Modo SSE Nativo (sin wrapper, sin variables dinámicas)

```yaml
services:
  ciber_analysis_mcp:
    networks:
      - agents_network
    image: maarifa-adk:v1
    build:
      dockerfile: ./assets/Dockerfile
    ports:
      - "12005:8080"
    environment:
      - SHODAN_API_KEY=${SHODAN_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
    command:
      - /bin/bash
      - -c
      - |
        source /root/.bashrc

        # Instalar nmap
        apt-get update && apt-get install -y nmap

        # Instalar el servidor desde GitHub
        pip install mcp-proxy mcp
        uv pip install --system git+https://github.com/tu-usuario/ciber-analysis-mcp-server.git

        # Clonar y ejecutar
        git clone https://github.com/tu-usuario/ciber-analysis-mcp-server.git /opt/ciber_mcp
        cd /opt/ciber_mcp

        # Ejecutar en modo SSE (puerto 8080)
        sed -i 's/localhost:8003/0.0.0.0:8080/g' ciber-analisys-mcp-server.py
        python3 ciber-analisys-mcp-server.py
```

## 🛠️ Herramientas Disponibles

### 1. `nmap_port_scan` - Escaneo de Puertos en Tiempo Real

Escanea puertos abiertos usando nmap con detección de servicios y versiones.

**Parámetros:**
- `ip` (str): Dirección IP a escanear (ej: "8.8.8.8")
- `port_range` (str, opcional): Rango de puertos (ej: "1-1000", "80,443,8080")
- `scan_type` (str, opcional): Tipo de escaneo
  - `"fast"`: Top 100 puertos más comunes (por defecto)
  - `"common"`: Puertos 1-1000
  - `"full"`: Todos los puertos (1-65535)
  - `"specific"`: Usa port_range personalizado

**Ejemplo:**
```json
{
  "ip": "192.168.1.1",
  "scan_type": "fast"
}
```

### 2. `get_host_info` - Información de Shodan

Obtiene datos históricos de una IP desde Shodan (requiere API key).

**Parámetros:**
- `ip` (str): Dirección IP a consultar

**Retorna:** Puertos, hostnames, organización, país, ciudad, ISP, ASN, última actualización

### 3. `geolocate_ip` - Geolocalización de IP

Geolocaliza una IP y obtiene información de red (GRATUITO, 45 req/min).

**Parámetros:**
- `ip` (str): Dirección IP a geolocalizar

**Retorna:** País, ciudad, ISP, ASN, coordenadas, timezone, flags (mobile, proxy, hosting)

### 4. `dns_lookup` - Consulta DNS

Realiza consultas DNS completas (GRATUITO, sin límites).

**Parámetros:**
- `domain` (str): Dominio a consultar (ej: "google.com")
- `record_type` (str, opcional): Tipo de registro (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR)

**Ejemplo:**
```json
{
  "domain": "google.com",
  "record_type": "MX"
}
```

### 5. `check_ip_reputation` - Verificación de Reputación

Verifica si una IP es maliciosa usando AbuseIPDB (requiere API key gratuita).

**Parámetros:**
- `ip` (str): Dirección IP a verificar

**Retorna:** Score de abuso (0-100), nivel de riesgo, reportes, categorías, flags

### 6. `whois_lookup` - Consulta WHOIS

Obtiene información WHOIS de dominios o IPs (GRATUITO).

**Parámetros:**
- `query` (str): Dominio o IP a consultar

**Retorna:** Propietario, registrar, fechas, nameservers, emails, país, DNSSEC

### 7. `get_my_ip` - Obtener IP Pública

Obtiene tu dirección IP pública actual (GRATUITO).

**Retorna:** Tu IP pública

## 📚 Integración con Claude Desktop

Añade al archivo `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ciber-analysis": {
      "command": "python",
      "args": ["/ruta/completa/a/ciber-analisys-mcp-server.py"],
      "env": {
        "SHODAN_API_KEY": "tu_api_key_aqui",
        "ABUSEIPDB_API_KEY": "tu_api_key_aqui"
      }
    }
  }
}
```

## 🔐 Uso Responsable y Ético

**IMPORTANTE**: Este servidor está diseñado EXCLUSIVAMENTE para análisis de seguridad defensiva y con fines educativos:

### ✅ Usos Permitidos:
- Análisis de vulnerabilidades de tus propios sistemas
- Auditorías de seguridad autorizadas por escrito
- Investigación educativa y académica
- Monitoreo de infraestructura propia
- Análisis forense autorizado

### ❌ Usos Prohibidos:
- Escaneo de redes o sistemas sin autorización explícita
- Actividades maliciosas o ilegales
- Ataques de denegación de servicio (DoS/DDoS)
- Acceso no autorizado a sistemas
- Recopilación no autorizada de información

**Responsabilidad Legal**: El usuario es el único responsable del uso de esta herramienta. Asegúrate de cumplir con todas las leyes y regulaciones aplicables en tu jurisdicción.

## 🎯 Ejemplos de Uso

### Análisis Completo de una IP

```python
# 1. Geolocalizar
resultado = await geolocate_ip("8.8.8.8")

# 2. Escanear puertos
resultado = await nmap_port_scan("8.8.8.8", scan_type="fast")

# 3. Verificar reputación
resultado = await check_ip_reputation("8.8.8.8")

# 4. WHOIS
resultado = await whois_lookup("8.8.8.8")
```

### Análisis de Dominio

```python
# 1. Resolver a IP
resultado = await dns_lookup("example.com", "A")

# 2. Verificar servidores de correo
resultado = await dns_lookup("example.com", "MX")

# 3. WHOIS del dominio
resultado = await whois_lookup("example.com")
```

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Para contribuir:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/amazing-feature`)
3. Commit tus cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 🔗 Enlaces Útiles

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [FastMCP Documentation](https://github.com/modelcontextprotocol/python-sdk)
- [Shodan API Documentation](https://developer.shodan.io/)
- [AbuseIPDB API](https://www.abuseipdb.com/)
- [nmap Documentation](https://nmap.org/book/man.html)

## 🐛 Reportar Issues

Si encuentras algún bug o tienes una sugerencia, por favor abre un issue en GitHub con:
- Descripción clara del problema
- Pasos para reproducirlo
- Versión de Python y sistema operativo
- Logs relevantes

## 📝 Changelog

### v1.0.0 (2025-10-17)
- ✨ Release inicial
- 🔍 Implementación de 7 herramientas de análisis
- 🐳 Soporte para Docker Compose con y sin wrapper
- 📚 Documentación completa
- 🔐 Enfoque en seguridad defensiva

---

**Desarrollado con ❤️ para la comunidad de ciberseguridad**
