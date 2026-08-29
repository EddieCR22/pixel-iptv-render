PIXEL IPTV RENDER V014 — CATÁLOGO EN VIVO DEFINITIVO

- Nuevo action get_live_catalog.
- Lee el M3U completo y toma group-title como fuente autoritativa de TV en vivo.
- Extrae nombre, logo, tvg-id y stream_id directamente del M3U.
- Fusiona Xtream solo para completar datos/canales faltantes; nunca elimina grupos M3U.
- Elimina la dependencia del join M3U ↔ Xtream que podía perder categorías.
- Reproductor y audio no se modifican respecto al backend anterior.
