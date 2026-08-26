PIXEL IPTV — BACKEND RENDER V001
================================

Este ZIP es el backend de prueba para Render.

ARCHIVOS
- server.js
- package.json
- render.yaml
- .gitignore

VARIABLES QUE DEBES CREAR EN RENDER
1) UPSTREAM_BASE
   Pon la URL base de tu proveedor IPTV, sin barra al final.
   Ejemplo de formato: http://servidor:puerto

2) TOKEN_SECRET
   Usa una frase aleatoria de al menos 32 caracteres.
   NO uses tu contraseña IPTV aquí.

3) ALLOWED_ORIGIN
   Para la primera prueba puedes dejar:
   *
   Luego se puede limitar al dominio de Pixel IPTV.

AJUSTES EN RENDER
- Tipo: Web Service
- Runtime: Node
- Build Command: npm install
- Start Command: npm start
- Instance Type: Free
- Health Check Path: /health

PRUEBA
Cuando Render termine, abre:
https://TU-SERVICIO.onrender.com/health

Debe responder con:
{"ok":true,"service":"Pixel IPTV Render Proxy","version":"V001",...}

IMPORTANTE
No publiques credenciales IPTV en GitHub.
Este proyecto NO incluye usuario ni contraseña del cliente.
Las credenciales se envían desde el formulario de Pixel IPTV y se guardan
solo dentro del token cifrado de la sesión.
