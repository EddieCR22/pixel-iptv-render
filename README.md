# Pixel IPTV Render V014

Backend compatible con Pixel IPTV Frontend V039.

## Corrección V014 — audio de Teletica / canales especiales
- El modo `audiofix` ya no entrega el audio corregido a través de MPEG-TS como primera opción.
- FFmpeg conserva el video original y convierte **solo el audio a AAC-LC 48 kHz estéreo**.
- La salida principal es **MP4 fragmentado (fMP4)** para que Chrome/Brave reproduzcan H.264 + AAC directamente.
- Se conserva `audiofixts` como respaldo con AAC dentro de MPEG-TS.
- No se transcodifican películas, series ni canales normales: el cambio solo se usa cuando el frontend solicita audio compatible.

## Seguridad conservada
- Sesión AES-256-GCM.
- Tickets temporales con alcance específico.
- Token independiente para imágenes.
- CORS limitado a `ALLOWED_ORIGIN`.
- Protección SSRF, límites de login y timeouts.

## Variables de Render
- `UPSTREAM_BASE`
- `TOKEN_SECRET` (32+ caracteres)
- `ALLOWED_ORIGIN` = `https://iptv.pixelservicecr.com`
- `PLAYER_REFERER` si el proveedor lo requiere.
- `PLAYER_ORIGIN` si el proveedor lo requiere.
