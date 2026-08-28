PIXEL IPTV RENDER V007

- Corrige el 403 del modo audiofix observado en V006.
- FFmpeg ya no abre directamente el stream del proveedor.
- La entrada de FFmpeg es el HLS ya validado y reescrito por Pixel IPTV Render.
- Los manifests y segmentos siguen usando los perfiles de cabecera/fallback que ya funcionan en HLS normal.
- Video H.264 se copia sin recodificar; audio se convierte a AAC estéreo 48 kHz.
- Preparado para frontend V031 con detección automática de canales sin audio decodificado.
