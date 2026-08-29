PIXEL IPTV RENDER V016 — CORRECCIÓN CATEGORÍAS + AUDIO

1) CATEGORÍAS QUE NO APARECÍAN (p.ej. Costa Rica)
Causa: solo se leía category_id (singular) de cada canal que entrega Xtream.
Muchos paneles devuelven las categorías reales en category_ids (arreglo) y
dejan category_id como valor secundario. Si ningún canal tenía "Costa Rica"
como categoría PRINCIPAL, la categoría quedaba con 0 canales y desaparecía
del filtro aunque existiera en el proveedor.
Corrección: se leen todas las category_ids de cada canal, no solo la primera.

2) SIN AUDIO EN TELETICA (y canales similares)
Causa: el reproductor usa hls.js/mpegts.js (MediaSource Extensions). Estos
canales entregan el audio original en AC-3/E-AC-3 (Dolby Digital), que el
navegador no puede decodificar dentro de MSE. El video se ve, el audio queda
mudo, sin ningún error visible. No es corregible desde el navegador.
Corrección: el proxy ahora retranscodifica SOLO el audio a AAC con ffmpeg
(video intacto, -c:v copy), tanto en los segmentos HLS como en el modo TS
directo, únicamente para contenido en vivo.

REQUIERE
- Nueva dependencia: ffmpeg-static (ya agregada a package.json).
- Render instala el binario de ffmpeg automáticamente en el build (npm install).
- No requiere cambios en el frontend (Pixel IPTV V042 sigue funcionando igual).

NO CAMBIA
- Login, perfiles, favoritos, episodios.
- Reproducción de películas/series (el transcode de audio es solo para "live").
- Diseño ni JS del cliente.
