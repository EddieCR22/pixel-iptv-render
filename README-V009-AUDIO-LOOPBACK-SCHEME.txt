PIXEL IPTV RENDER V009

- Corrige el fallo exacto detectado en Logs: "An unexpected TLS packet was received".
- Cuando FFmpeg entra por http://127.0.0.1, las playlists HLS ahora reescriben segmentos también a HTTP loopback.
- Evita que FFmpeg intente HTTPS/TLS contra el servidor HTTP interno de Node.
- Mantiene el video sin recodificar y convierte el audio a AAC estéreo 48 kHz.
- /health informa audioFixLoopbackSchemeFix: true.
