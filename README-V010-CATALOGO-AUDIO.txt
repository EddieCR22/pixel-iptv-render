PIXEL IPTV RENDER V010

- Permite category_id en get_live_streams, get_vod_streams y get_series para recuperar categorías de forma selectiva.
- Amplía el timeout JSON del catálogo de 15 s a 25 s.
- Mantiene Render V009 y su corrección loopback/TLS.
- Audiofix usa loglevel info y exige una pista de audio real; ya no puede devolver video-only como si la corrección hubiera funcionado.
- Corrige los textos de arranque/apagado que todavía mostraban V008.
- /health informa categoryScopedCatalog, catalogJsonTimeoutMs y audioInputRequired.
