"""
Servidor MCP para Shodan usando mcp oficial + SSE
Compatible con Google ADK
"""

import os
import httpx
import subprocess
import asyncio
from typing import Dict, Any, List

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.routing import Route, Mount

from mcp.server.fastmcp import FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, INTERNAL_ERROR
from mcp.server.sse import SseServerTransport

# Configuración
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "DeJ9mG7nRjhjlQFAl2UVxQ79emjFa3br")
SHODAN_API_BASE = "https://api.shodan.io"
INTERNETDB_BASE = "https://internetdb.shodan.io"

# Crear instancia de servidor MCP
mcp = FastMCP("shodan-security-server")


@mcp.tool()
async def get_host_info(ip: str) -> Dict[str, Any]:
    """
    Obtiene información básica sobre una IP usando la API de Shodan.
    Requiere API key configurada.

    Args:
        ip: Dirección IP a consultar (ej: 8.8.8.8)

    Returns:
        Diccionario con información del host
    """
    if not SHODAN_API_KEY:
        return {
            "success": False,
            "error": "No se configuró SHODAN_API_KEY. Usa internetdb_lookup para búsquedas sin API key."
        }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{SHODAN_API_BASE}/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY, "minify": True},
                timeout=15.0
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "ip": data.get("ip_str"),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "organization": data.get("org", "N/A"),
                    "country": data.get("country_name", "N/A"),
                    "city": data.get("city", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "asn": data.get("asn", "N/A"),
                    "last_update": data.get("last_update", "N/A")
                }
            else:
                return {
                    "success": False,
                    "error": f"Error HTTP {response.status_code}: {response.text}"
                }

    except Exception as e:
        return {
            "success": False,
            "error": f"Error al consultar Shodan: {str(e)}"
        }


@mcp.tool()
async def get_my_ip() -> Dict[str, str]:
    """
    Obtiene tu dirección IP pública actual.
    Esta operación es GRATUITA y funciona sin API key.

    Returns:
        Diccionario con tu IP pública
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.ipify.org?format=json",
                timeout=10.0
            )
            if response.status_code == 200:
                return {
                    "success": True,
                    **response.json()
                }
    except Exception as e:
        return {
            "success": False,
            "error": f"No se pudo obtener la IP: {str(e)}"
        }

    return {
        "success": False,
        "error": "No se pudo obtener la IP"
    }


@mcp.tool()
async def nmap_port_scan(
    ip: str,
    port_range: str = "1-1000",
    scan_type: str = "fast"
) -> Dict[str, Any]:
    """
    Escanea puertos abiertos en tiempo real usando nmap.

    Args:
        ip: Dirección IP a escanear
        port_range: Rango de puertos (ej: "1-1000", "80,443,8080", "1-65535")
        scan_type: Tipo de escaneo:
            - "fast": Top 100 puertos más comunes (-F)
            - "common": Top 1000 puertos (-p 1-1000)
            - "full": Todos los puertos (-p-)
            - "specific": Usa port_range personalizado

    Returns:
        Diccionario con puertos abiertos, servicios y versiones detectadas
    """
    try:
        # Validar IP básica
        parts = ip.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return {
                "success": False,
                "error": "IP inválida. Formato esperado: X.X.X.X"
            }

        # Construir comando nmap
        cmd = ["nmap"]

        if scan_type == "fast":
            cmd.append("-F")  # Top 100 puertos
        elif scan_type == "full":
            cmd.append("-p-")  # Todos los puertos
        elif scan_type == "specific":
            cmd.extend(["-p", port_range])
        else:  # common
            cmd.extend(["-p", "1-1000"])

        # Opciones comunes
        cmd.extend([
            "-sV",  # Detectar versiones
            "-T4",  # Timing agresivo
            "--open",  # Solo puertos abiertos
            ip
        ])

        # Ejecutar nmap de forma asíncrona
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=120.0  # 2 minutos timeout
        )

        output = stdout.decode()

        # Parsear resultados
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    if len(parts) > 3:
                        port_info["version"] = " ".join(parts[3:])
                    ports.append(port_info)

        return {
            "success": True,
            "ip": ip,
            "scan_type": scan_type,
            "ports_found": len(ports),
            "ports": ports,
            "raw_output": output if ports else "No se encontraron puertos abiertos",
            "note": "Escaneo en tiempo real con nmap"
        }

    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": "Timeout: El escaneo tardó más de 2 minutos"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "nmap no está instalado. Instala con: sudo apt install nmap"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error al ejecutar nmap: {str(e)}"
        }


@mcp.tool()
async def geolocate_ip(ip: str) -> Dict[str, Any]:
    """
    Geolocaliza una IP y obtiene información sobre su ubicación, ISP y organización.
    Completamente GRATUITO (45 peticiones/minuto).

    Args:
        ip: Dirección IP a geolocalizar (ej: 8.8.8.8)

    Returns:
        Diccionario con país, ciudad, ISP, ASN, coordenadas, timezone
    """
    try:
        # Validar IP
        import ipaddress
        ipaddress.ip_address(ip)

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query",
                timeout=10.0
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("status") == "fail":
                    return {
                        "success": False,
                        "error": data.get("message", "IP inválida o privada")
                    }

                return {
                    "success": True,
                    "ip": data.get("query"),
                    "location": {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone")
                    },
                    "network": {
                        "isp": data.get("isp"),
                        "organization": data.get("org"),
                        "asn": data.get("as"),
                        "asn_name": data.get("asname")
                    },
                    "flags": {
                        "is_mobile": data.get("mobile", False),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False)
                    },
                    "note": "Límite: 45 peticiones/minuto"
                }
            else:
                return {
                    "success": False,
                    "error": f"Error HTTP {response.status_code}"
                }

    except ValueError:
        return {
            "success": False,
            "error": "Formato de IP inválido"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error al geolocalizar: {str(e)}"
        }


@mcp.tool()
async def dns_lookup(domain: str, record_type: str = "A") -> Dict[str, Any]:
    """
    Realiza consultas DNS de un dominio (A, AAAA, MX, TXT, NS, CNAME, etc.).
    Completamente GRATUITO y sin límites.

    Args:
        domain: Dominio a consultar (ej: google.com)
        record_type: Tipo de record DNS (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR)

    Returns:
        Diccionario con los records encontrados
    """
    try:
        import dns.resolver
        import dns.reversename

        record_type = record_type.upper()

        # Si es PTR, convertir IP a formato reverse
        if record_type == "PTR":
            try:
                import ipaddress
                ip = ipaddress.ip_address(domain)
                domain = dns.reversename.from_address(str(ip))
            except:
                pass

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            answers = resolver.resolve(domain, record_type)
            records = []

            for rdata in answers:
                if record_type == "A":
                    records.append(str(rdata))
                elif record_type == "AAAA":
                    records.append(str(rdata))
                elif record_type == "MX":
                    records.append({
                        "priority": rdata.preference,
                        "server": str(rdata.exchange)
                    })
                elif record_type == "TXT":
                    records.append(str(rdata).strip('"'))
                elif record_type == "NS":
                    records.append(str(rdata))
                elif record_type == "CNAME":
                    records.append(str(rdata))
                elif record_type == "SOA":
                    records.append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum
                    })
                elif record_type == "PTR":
                    records.append(str(rdata))
                else:
                    records.append(str(rdata))

            return {
                "success": True,
                "domain": str(domain),
                "record_type": record_type,
                "records": records,
                "total": len(records)
            }

        except dns.resolver.NXDOMAIN:
            return {
                "success": False,
                "error": f"Dominio no existe: {domain}"
            }
        except dns.resolver.NoAnswer:
            return {
                "success": False,
                "error": f"No hay records {record_type} para {domain}"
            }
        except dns.resolver.Timeout:
            return {
                "success": False,
                "error": "Timeout al consultar DNS"
            }

    except Exception as e:
        return {
            "success": False,
            "error": f"Error en DNS lookup: {str(e)}"
        }


@mcp.tool()
async def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Verifica la reputación de una IP en bases de datos de abuso (AbuseIPDB).
    Detecta si la IP ha sido reportada por actividades maliciosas.
    REQUIERE API KEY de AbuseIPDB (gratis: 1000 checks/día).

    Args:
        ip: Dirección IP a verificar (ej: 192.0.2.1)

    Returns:
        Diccionario con score de abuso, categorías, reportes
    """
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

    if not ABUSEIPDB_API_KEY:
        return {
            "success": False,
            "error": "No se configuró ABUSEIPDB_API_KEY. Obtén una gratis en: https://www.abuseipdb.com/register",
            "note": "API key gratuita: 1000 checks/día"
        }

    try:
        import ipaddress
        ipaddress.ip_address(ip)

        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": ""
                },
                timeout=10.0
            )

            if response.status_code == 200:
                result = response.json()
                data = result.get("data", {})

                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)

                # Determinar nivel de riesgo
                if abuse_score == 0:
                    risk_level = "SEGURO"
                    risk_emoji = "✅"
                elif abuse_score < 25:
                    risk_level = "BAJO"
                    risk_emoji = "🟢"
                elif abuse_score < 50:
                    risk_level = "MEDIO"
                    risk_emoji = "🟡"
                elif abuse_score < 75:
                    risk_level = "ALTO"
                    risk_emoji = "🟠"
                else:
                    risk_level = "CRÍTICO"
                    risk_emoji = "🔴"

                return {
                    "success": True,
                    "ip": ip,
                    "abuse_score": abuse_score,
                    "risk_level": risk_level,
                    "risk_emoji": risk_emoji,
                    "total_reports": total_reports,
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "is_tor": data.get("isTor", False),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "last_reported": data.get("lastReportedAt"),
                    "categories": data.get("reports", [])[:5] if data.get("reports") else [],
                    "note": f"Score 0-100: {abuse_score}. Mayor = más peligrosa"
                }
            elif response.status_code == 429:
                return {
                    "success": False,
                    "error": "Límite de rate alcanzado (1000/día con API key gratuita)"
                }
            elif response.status_code == 401:
                return {
                    "success": False,
                    "error": "API key inválida. Verifica ABUSEIPDB_API_KEY"
                }
            else:
                return {
                    "success": False,
                    "error": f"Error HTTP {response.status_code}"
                }

    except ValueError:
        return {
            "success": False,
            "error": "Formato de IP inválido"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error al verificar reputación: {str(e)}"
        }


@mcp.tool()
async def whois_lookup(query: str) -> Dict[str, Any]:
    """
    Consulta información WHOIS de un dominio o IP.
    Obtiene propietario, registrar, fechas de registro/expiración, nameservers.
    GRATUITO pero puede tener límites por proveedor WHOIS.

    Args:
        query: Dominio (ej: google.com) o IP (ej: 8.8.8.8)

    Returns:
        Diccionario con información del propietario y registro
    """
    try:
        import whois as whois_module

        # Realizar consulta WHOIS
        w = whois_module.whois(query)

        # Procesar datos (WHOIS puede devolver diferentes formatos)
        result = {
            "success": True,
            "query": query,
        }

        # Información del dominio
        if hasattr(w, 'domain_name'):
            result["domain_name"] = w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else None)

        # Registrar
        if hasattr(w, 'registrar'):
            result["registrar"] = w.registrar

        # Fechas
        dates = {}
        if hasattr(w, 'creation_date'):
            cd = w.creation_date
            dates["created"] = str(cd[0] if isinstance(cd, list) else cd) if cd else None
        if hasattr(w, 'updated_date'):
            ud = w.updated_date
            dates["updated"] = str(ud[0] if isinstance(ud, list) else ud) if ud else None
        if hasattr(w, 'expiration_date'):
            ed = w.expiration_date
            dates["expires"] = str(ed[0] if isinstance(ed, list) else ed) if ed else None

        if dates:
            result["dates"] = dates

        # Nameservers
        if hasattr(w, 'name_servers'):
            ns = w.name_servers
            result["nameservers"] = list(ns) if ns else []

        # Estado
        if hasattr(w, 'status'):
            status = w.status
            result["status"] = list(status) if isinstance(status, list) else [status] if status else []

        # Organización
        if hasattr(w, 'org'):
            result["organization"] = w.org

        # Emails
        if hasattr(w, 'emails'):
            emails = w.emails
            result["emails"] = list(emails) if isinstance(emails, list) else [emails] if emails else []

        # País
        if hasattr(w, 'country'):
            result["country"] = w.country

        # DNSSEC
        if hasattr(w, 'dnssec'):
            result["dnssec"] = w.dnssec

        return result

    except Exception as e:
        error_msg = str(e)

        # Detectar errores comunes
        if "No match" in error_msg or "NOT FOUND" in error_msg:
            return {
                "success": False,
                "error": f"Dominio/IP no encontrado en WHOIS: {query}"
            }
        elif "connect" in error_msg.lower() or "timeout" in error_msg.lower():
            return {
                "success": False,
                "error": "Timeout al conectar con servidor WHOIS. Intenta de nuevo."
            }
        else:
            return {
                "success": False,
                "error": f"Error en WHOIS lookup: {error_msg}"
            }


# Configurar SSE transport
sse = SseServerTransport("/messages/")


async def handle_sse(request: Request):
    """Handler para conexiones SSE desde clientes MCP"""
    _server = mcp._mcp_server
    async with sse.connect_sse(
        request.scope,
        request.receive,
        request._send,
    ) as (reader, writer):
        await _server.run(reader, writer, _server.create_initialization_options())
    # Devolver respuesta vacía después de cerrar conexión SSE
    return StreamingResponse(iter([]), media_type="text/event-stream")


# Crear aplicación Starlette
app = Starlette(
    debug=True,
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ],
)


#if __name__ == "__main__":
#    print("🚀 Servidor MCP Shodan Security Agent iniciando...")
#    print(f"🔑 Shodan API Key: {'✅ Configurada' if SHODAN_API_KEY else '❌ No configurada'}")
#    print(f"🔑 AbuseIPDB API Key: {'✅ Configurada' if os.getenv('ABUSEIPDB_API_KEY') else '⚠️  No configurada (opcional)'}")
#    print(f"🌐 SSE endpoint: http://localhost:8003/sse")
#    print(f"\n📡 Herramientas disponibles (7 tools):")
#    print(f"   🔍 Port Scanning & Reconnaissance:")
#    print(f"      - nmap_port_scan (escaneo en tiempo real, requiere nmap) ⭐ NUEVO")
#    print(f"      - get_host_info (requiere Shodan API key)")
#    print(f"   🌍 Geolocalización & Red:")
#    print(f"      - geolocate_ip (gratuito, 45 req/min)")
#    print(f"      - dns_lookup (gratuito, ilimitado)")
#    print(f"   🛡️ Seguridad:")
#    print(f"      - check_ip_reputation (AbuseIPDB)")
#    print(f"      - whois_lookup (gratuito)")
#    print(f"   🔧 Utilidades:")
#    print(f"      - get_my_ip (gratuito)")
#    print(f"\n✅ Servidor listo para conexiones MCP")
#    uvicorn.run(app, host="localhost", port=8003)
def main():
    """Entry point for the CLI command"""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

if __name__ == "__main__":
    main()
