import email
from email import policy
from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status


class HTMLLinkExtractor(HTMLParser):

    def __init__(self) -> None:
        super().__init__()
        self.urls: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    cleaned = attr_val.strip()
                    if cleaned.lower().startswith(("http://", "https://")):
                        self.urls.append(cleaned)


URL_REGEX = re.compile(r'https?://[^\s<>"\'`()\[\]{}]+', re.IGNORECASE)


def _clean_url(url: str) -> str:
    cleaned = url.strip().strip('"\'<>')
    return cleaned.rstrip(".,;:!?)>]}")


def _extract_auth_status(header_text: str, protocol: str) -> str:
    if not header_text:
        return "none"

    pattern = rf"\b{protocol}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b"
    match = re.search(pattern, header_text, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    if protocol == "spf":
        spf_direct = re.search(r"^(pass|fail|softfail|neutral|none)\b", header_text.strip(), re.IGNORECASE)
        if spf_direct:
            return spf_direct.group(1).lower()

    return "none"


def _extract_urls_from_text(text: str) -> List[str]:
    found: List[str] = []
    for match in URL_REGEX.findall(text):
        clean = _clean_url(match)
        if clean.lower().startswith(("http://", "https://")):
            found.append(clean)
    return found


def _extract_urls_from_html(html_text: str) -> List[str]:
    found: List[str] = []

    try:
        parser = HTMLLinkExtractor()
        parser.feed(html_text)
        for u in parser.urls:
            clean = _clean_url(u)
            if clean.lower().startswith(("http://", "https://")):
                found.append(clean)
    except Exception:
        pass

    for match in URL_REGEX.findall(html_text):
        clean = _clean_url(match)
        if clean.lower().startswith(("http://", "https://")):
            found.append(clean)

    return found


def parse_eml(file_bytes: bytes) -> Dict[str, Any]:

    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo proporcionado está vacío.",
        )

    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Formato de archivo .eml no válido o corrupto: {str(exc)}",
        )

    metadata = {
        "from": str(msg.get("From", "Desconocido")),
        "to": str(msg.get("To", "Desconocido")),
        "subject": str(msg.get("Subject", "Sin Asunto")),
        "date": str(msg.get("Date", "Desconocida")),
        "return_path": str(msg.get("Return-Path", "")),
        "message_id": str(msg.get("Message-ID", "")),
    }

    auth_results_list = msg.get_all("Authentication-Results", [])
    received_spf_list = msg.get_all("Received-SPF", [])

    auth_combined = " ".join([str(h) for h in auth_results_list])
    spf_combined = " ".join([str(h) for h in received_spf_list])
    all_headers_auth = f"{auth_combined} {spf_combined}"

    spf_status = _extract_auth_status(all_headers_auth, "spf")
    if spf_status == "none" and spf_combined:
        spf_status = _extract_auth_status(spf_combined, "spf")

    dkim_status = _extract_auth_status(all_headers_auth, "dkim")
    if dkim_status == "none" and msg.get("DKIM-Signature"):
        dkim_status = "present_unverified"

    dmarc_status = _extract_auth_status(all_headers_auth, "dmarc")

    security_headers = {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "authentication_results": auth_combined.strip() or None,
        "received_spf": spf_combined.strip() or None,
    }

    raw_urls: List[str] = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        text = part.get_content()
                        if isinstance(text, str):
                            raw_urls.extend(_extract_urls_from_text(text))
                    except Exception:
                        payload_bytes = part.get_payload(decode=True)
                        if payload_bytes:
                            for enc in ("utf-8", "latin-1", "windows-1252"):
                                try:
                                    raw_urls.extend(_extract_urls_from_text(payload_bytes.decode(enc)))
                                    break
                                except Exception:
                                    continue
                elif content_type == "text/html":
                    try:
                        html_text = part.get_content()
                        if isinstance(html_text, str):
                            raw_urls.extend(_extract_urls_from_html(html_text))
                    except Exception:
                        payload_bytes = part.get_payload(decode=True)
                        if payload_bytes:
                            for enc in ("utf-8", "latin-1", "windows-1252"):
                                try:
                                    raw_urls.extend(_extract_urls_from_html(payload_bytes.decode(enc)))
                                    break
                                except Exception:
                                    continue
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if isinstance(content, str):
                    if content_type == "text/html":
                        raw_urls.extend(_extract_urls_from_html(content))
                    else:
                        raw_urls.extend(_extract_urls_from_text(content))
            except Exception:
                body_bytes = msg.get_payload(decode=True)
                if body_bytes:
                    text = body_bytes.decode("utf-8", errors="ignore")
                    if content_type == "text/html":
                        raw_urls.extend(_extract_urls_from_html(text))
                    else:
                        raw_urls.extend(_extract_urls_from_text(text))

    except Exception:
        pass

    cleaned_urls: List[str] = []
    seen = set()
    for u in raw_urls:
        if u and u not in seen:
            seen.add(u)
            cleaned_urls.append(u)

    return {
        "metadata": metadata,
        "security_headers": security_headers,
        "urls": cleaned_urls,
        "urls_count": len(cleaned_urls),
    }
