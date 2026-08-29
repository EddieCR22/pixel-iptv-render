PIXEL IPTV RENDER V013 — CATEGORÍAS M3U

BASE: Render V005.

CAMBIO ÚNICO FUNCIONAL
- Añade action=get_live_groups en /api/data.
- Lee group-title de la lista M3U del mismo usuario autenticado.
- Devuelve solo stream_id + nombre de grupo; nunca devuelve credenciales ni URLs del proveedor.
- Cache temporal de 10 minutos para no ralentizar el catálogo.

NO SE CAMBIA
- Login.
- Tickets.
- Reproductor/streams.
- HLS/TS.
- Imágenes.
- Seguridad de V005.
