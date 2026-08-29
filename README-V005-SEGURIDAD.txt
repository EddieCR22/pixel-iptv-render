PIXEL IPTV RENDER V005 — SECURITY
- CORS deja de usar * y requiere https://iptv.pixelservicecr.com.
- Más headers defensivos.
- Login limitado a 12 intentos/10 min por IP por instancia.
- requestTimeout 30s.
- Mantiene cifrado AES-256-GCM, tickets, SSRF protection y flujos V004.
