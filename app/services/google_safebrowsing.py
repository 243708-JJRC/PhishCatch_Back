from typing import Any, Dict
import httpx

from app.core.config import settings

SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_safe_browsing(url: str) -> Dict[str, Any]:
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return {
            "risk_level": "unknown",
            "error": "Google Safe Browsing API key no configurada.",
            "details": {},
        }

    payload = {
        "client": {
            "clientId": "phishcatch",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{SAFE_BROWSING_API_URL}?key={api_key}",
                json=payload,
            )
            response.raise_for_status()
            resp_json = response.json()

        matches = resp_json.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
            return {
                "risk_level": "malicious",
                "threat_types": threat_types,
                "details": resp_json,
            }

        return {
            "risk_level": "safe",
            "details": {
                "status": "clean",
                "message": "Google Safe Browsing no encontró amenazas de malware ni phishing.",
                "matches": []
            }
        }

    except httpx.TimeoutException:
        return {
            "risk_level": "unknown",
            "error": "Tiempo de espera agotado al conectar con Google Safe Browsing.",
            "details": {},
        }
    except httpx.HTTPStatusError as exc:
        return {
            "risk_level": "unknown",
            "error": f"Error HTTP {exc.response.status_code} al consultar Google Safe Browsing.",
            "details": {},
        }
    except httpx.RequestError as exc:
        return {
            "risk_level": "unknown",
            "error": f"Error de red o comunicación con Google Safe Browsing: {str(exc)}",
            "details": {},
        }
    except Exception as exc:
        return {
            "risk_level": "unknown",
            "error": f"Error inesperado al procesar Google Safe Browsing: {str(exc)}",
            "details": {},
        }

