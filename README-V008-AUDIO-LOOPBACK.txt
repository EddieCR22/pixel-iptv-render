PIXEL IPTV RENDER V008

- Audiofix usa el proxy HLS interno por 127.0.0.1 en vez de volver a entrar por el dominio público de Render.
- Mantiene video sin recodificar y convierte audio a AAC estéreo 48 kHz.
- Añade aresample async para corregir timestamps de audio irregulares.
- Añade diagnósticos seguros [audiofix] en Logs sin exponer tickets.
- /health informa audioFixLoopback y audioFixDiagnostics.
