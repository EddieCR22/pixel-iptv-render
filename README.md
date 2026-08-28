# Pixel IPTV Render V013

Backend compatible con Pixel IPTV Frontend V038.

## Funciones conservadas
- Inicio de sesión Xtream y sesión cifrada AES-256-GCM.
- Catálogos de películas, series y TV en vivo.
- Normalización de categorías en vivo mediante `group-title` del M3U cuando está disponible.
- Tokens separados para imágenes y tickets temporales para reproducción.
- Proxy HLS recursivo y segmentos protegidos.
- MPEG-TS, MP4 y compatibilidad VOD HLS/MP4/TS.
- Modo `audiofix` con FFmpeg para canales que requieren audio AAC compatible.
- Protección SSRF para imágenes y redirecciones, límites de login, timeouts y CORS restringido.

## Endurecimiento V013
- Se elimina la compatibilidad antigua que permitía usar el token principal de sesión en URLs de streams.
- `/image` acepta exclusivamente tokens de alcance `image`.
- El frontend V038 solicita un ticket nuevo al cambiar entre HLS, MPEG-TS y modos VOD, evitando reutilizar un ticket de un modo distinto.

## Variables de Render
- `UPSTREAM_BASE`: URL base de tu proveedor Xtream.
- `TOKEN_SECRET`: secreto aleatorio de al menos 32 caracteres.
- `ALLOWED_ORIGIN`: `https://iptv.pixelservicecr.com`
- `PLAYER_REFERER`: referer requerido por el proveedor, si aplica.
- `PLAYER_ORIGIN`: origin requerido por el proveedor, si aplica.

No publiques `UPSTREAM_BASE`, credenciales de clientes ni `TOKEN_SECRET` en GitHub.
