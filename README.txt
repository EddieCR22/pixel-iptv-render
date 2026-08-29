PIXEL IPTV RENDER V004

CORRECCIONES:
- Corrige una condición que podía cerrar la instancia con status 1 al abandonar streams.
- El apagado controlado de Render ya no fuerza exit(1).
- Normaliza Content-Type para MP4/TS cuando el proveedor lo envía vacío o como octet-stream.
- Películas/series pueden solicitar alternativas HLS, TS y MP4 al proveedor.
- Mantiene tickets temporales y seguridad de Render V003.
- Mejor manejo de sockets cerrados por el cliente.

NUEVO /health:
version: V004
vodCompatibilityFallbacks: true
normalizedMediaTypes: true
safeStreamShutdown: true
