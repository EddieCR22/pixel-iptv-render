PIXEL IPTV RENDER V002

CAMBIO PRINCIPAL
V001 abortaba inmediatamente cuando la primera ruta devolvía 403.
V002 prueba rutas alternativas Y varios perfiles de cabeceras antes de rendirse.

ESTRATEGIAS
- VLC
- ExoPlayer
- Navegador
- Android TV
- Rutas Xtream /live/... y /usuario/clave/...
- Los segmentos HLS recuerdan el perfil que logró abrir el manifest.

VARIABLES EXISTENTES
UPSTREAM_BASE
TOKEN_SECRET
ALLOWED_ORIGIN

NUEVAS VARIABLES OPCIONALES
PLAYER_REFERER=https://nubweb.nubservices.com/
PLAYER_ORIGIN=https://nubweb.nubservices.com

Si no las agregas, V002 ya usa esos valores como predeterminados.

IMPORTANTE
Si después de todas las rutas/perfiles el upstream sigue devolviendo 403,
el proveedor probablemente está bloqueando la IP/datacenter de Render.
