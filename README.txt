PIXEL IPTV RENDER V003

Revisión integral del backend.

MEJORAS PRINCIPALES
- Sesiones inválidas/vencidas devuelven 401 en vez de 500.
- Tickets de reproducción de corta duración: el token general ya no necesita viajar en la URL del video.
- Token separado para imágenes.
- Compatibilidad temporal con frontend V022 durante el despliegue.
- Rutas alternativas y perfiles VLC / ExoPlayer / navegador / Android TV.
- Timeouts reales para API, streams e imágenes.
- Manifests HLS validados y reescritos; sus segmentos heredan el perfil que funcionó.
- Los tickets de segmentos duran como máximo lo que dura la sesión.
- Se rechaza HTML cuando se esperaba video.
- Protección adicional del proxy de imágenes contra hosts privados y redirects peligrosos.
- Rate limit básico de login por IP.
- IDs y extensiones validados.
- Cierre de streams cuando el cliente abandona la reproducción.
- Cierre ordenado SIGTERM/SIGINT para deploys de Render.

VARIABLES REQUERIDAS
UPSTREAM_BASE
TOKEN_SECRET (32+ caracteres)
ALLOWED_ORIGIN

OPCIONALES
PLAYER_REFERER=https://nubweb.nubservices.com/
PLAYER_ORIGIN=https://nubweb.nubservices.com
