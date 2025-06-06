# AstroCypher Bot

## Descripción

AstroCypher Bot es un bot de Telegram que permite a los usuarios cifrar y descifrar mensajes de forma segura utilizando el algoritmo RSA. Facilita la comunicación privada entre usuarios de Telegram mediante criptografía asimétrica.

## Características

- **Cifrado RSA**: Utiliza el algoritmo RSA con claves de 2048 bits para un cifrado seguro
- **Gestión de contactos**: Selección de contactos para enviar mensajes cifrados
- **Mensajes automáticos**: Notificación automática al destinatario cuando recibe un mensaje cifrado
- **Base de datos**: Almacenamiento de claves y mensajes en SQLite
- **Interfaz amigable**: Menús interactivos con botones para una experiencia intuitiva

## Funcionalidades

- Establecer claves criptográficas personales
- Cifrar mensajes para contactos específicos
- Descifrar mensajes recibidos
- Listar mensajes cifrados (enviados/recibidos)
- Ver/eliminar claves personales
- Listar claves públicas disponibles
- Eliminar mensajes almacenados

## Requisitos

- Python 3.7+
- Bibliotecas de Python:
  - python-telegram-bot
  - cryptography
  - python-dotenv
  - sqlite3 (incluido en Python)

## Instalación

1. Clona este repositorio:

   git clone <https://github.com/tu-usuario/astrocypher-bot.git>
   cd astrocypher-bot

2. Instala las dependencias:

   pip install -r requirements.txt

3. Crea un archivo .env con tu token de bot de Telegram:

   BOT_TOKEN=tu_token_de_bot_aqui

4. Ejecuta el bot:
   python bot.py

## Uso

1. Inicia una conversación con el bot en Telegram usando `/start`
2. Establece tu clave personal
3. Selecciona contactos para enviar mensajes cifrados
4. Intercambia mensajes seguros con otros usuarios

## Estructura de la base de datos

El bot utiliza SQLite con dos tablas principales:

1. **usuarios**: Almacena información de usuario y claves
   - id: ID de usuario de Telegram
   - alias: Nombre de usuario
   - clave_publica: Clave pública en formato PEM
   - clave_privada: Clave privada en formato PEM
   - chat_id: ID de chat de Telegram

2. **mensajes**: Almacena mensajes cifrados
   - id: ID único del mensaje
   - user_id: ID del usuario relacionado
   - mensaje_cifrado: Mensaje cifrado en base64
   - tipo: Indicador si el mensaje fue 'enviado' o 'recibido'

## Seguridad

- Las claves privadas se almacenan localmente en la base de datos
- Los mensajes se cifran con RSA-2048 usando OAEP y SHA-256
- El formato de los mensajes cifrados es Base64 para facilitar la transmisión

## Contribuciones

Las contribuciones son bienvenidas. Para cambios importantes, abra primero un issue para discutir lo que le gustaría cambiar.

## Licencia

MIT License

Copyright (c) 2025 ASTROCRYPT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

CREADO POR ASTROCRYPT 2025
