PIXEL IPTV RENDER V015 — CATEGORÍAS COMPLETAS

Corrección única sobre V014:
- Conserva SIEMPRE la categoría oficial Xtream de cada canal.
- Conserva TAMBIÉN el group-title del M3U como categoría adicional.
- Un canal puede pertenecer a ambas categorías sin duplicarse.
- Se preservan IDs y orden de categorías oficiales.
- Se agregan grupos M3U que no existan en Xtream.
- No cambia reproducción, HLS, MPEG-TS ni audio.

Causa corregida:
V014 descartaba la categoría oficial cuando un canal ya aparecía en el M3U.
Esto podía reducir la lista visible a los pocos grupos M3U aunque existieran
muchas más categorías oficiales en get_live_categories.
