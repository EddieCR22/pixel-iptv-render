Pixel IPTV Render V011

Base: V010 / seguridad V005.
Cambio principal: audiofix deja de depender solo del HLS.
1) intenta el MPEG-TS original a través del proxy interno seguro;
2) exige una pista de video y una de audio;
3) copia el video sin recodificar y convierte el audio a AAC;
4) si TS falla, intenta HLS;
5) nunca declara éxito si solo recibió video silencioso.
