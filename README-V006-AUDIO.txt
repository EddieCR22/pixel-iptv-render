PIXEL IPTV RENDER V006 — CORRECCIÓN DE AUDIO

NUEVO:
- Agrega mode=audiofix para canales HLS con video pero audio no compatible con Chromium.
- El servidor abre la fuente HLS internamente con FFmpeg.
- Copia el video sin recodificar y convierte únicamente el audio a AAC estéreo 48 kHz.
- El navegador recibe MPEG-TS compatible mediante mpegts.js.
- Mantiene tickets temporales; no expone usuario/contraseña del proveedor al navegador.
- Limita transcodificaciones simultáneas (2 por defecto) para proteger la instancia.

/health debe indicar version V006, audioTranscodeFallback=true y ffmpegConfigured=true.
