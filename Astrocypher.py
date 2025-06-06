from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes, ConversationHandler
import logging
from dotenv import load_dotenv
import os
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64  # Importar el módulo base64
import sys  # Importar el módulo sys

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Obtener el token del bot desde las variables de entorno
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# Configurar logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# Modificar la tabla usuarios para incluir el chat_id
def crear_tabla_usuarios():
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY,
                alias TEXT NOT NULL,
                clave_publica BLOB NOT NULL,
                clave_privada BLOB NOT NULL,
                chat_id INTEGER NOT NULL
            );
        ''')
        conn.commit()
    except sqlite3.DatabaseError as e:
        logging.error(f"Error al crear la tabla usuarios: {e}")
    finally:
        conn.close()

# Crear la tabla mensajes si no existe
def crear_tabla_mensajes():
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        # Eliminar la tabla existente si existe
        c.execute('DROP TABLE IF EXISTS mensajes')
        # Crear la tabla con la nueva estructura
        c.execute('''
            CREATE TABLE mensajes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                mensaje_cifrado BLOB NOT NULL,
                tipo TEXT NOT NULL,  -- Nuevo campo para indicar si el mensaje fue enviado o recibido
                FOREIGN KEY (user_id) REFERENCES usuarios (id)
            )
        ''')
        conn.commit()
    except sqlite3.DatabaseError as e:
        logging.error(f"Error al crear la tabla mensajes: {e}")
    finally:
        conn.close()

# Llamar a las funciones para crear las tablas
crear_tabla_usuarios()
crear_tabla_mensajes()

# Estados para el ConversationHandler
SET_CLAVE, CIFRAR_ALIAS, CIFRAR_MENSAJE, DESCIFRAR_MENSAJE, ENVIAR_MENSAJE, CONTINUAR, SELECCIONAR_CONTACTO = range(7)

def generar_claves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def cifrar_mensaje_rsa(mensaje, public_key):
    mensaje_cifrado = public_key.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje_cifrado

def descifrar_mensaje_rsa(mensaje_cifrado, private_key):
    mensaje_descifrado = private_key.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje_descifrado.decode()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info("Comando /start recibido")
    keyboard = [
        [InlineKeyboardButton("Establecer Clave", callback_data='set_clave')],
        [InlineKeyboardButton("Cifrar Mensaje", callback_data='cifrar')],
        [InlineKeyboardButton("Descifrar Mensaje", callback_data='descifrar')],
        [InlineKeyboardButton("Listar Mensajes", callback_data='listar_mensajes')],
        [InlineKeyboardButton("Listar Claves", callback_data='listar_claves')],
        [InlineKeyboardButton("Eliminar Clave", callback_data='eliminar_clave')],
        [InlineKeyboardButton("Ver Mi Clave", callback_data='ver_mi_clave')],
        [InlineKeyboardButton("Eliminar Mensajes", callback_data='eliminar_mensajes')],
        [InlineKeyboardButton("Seleccionar Contacto", callback_data='seleccionar_contacto')],
        [InlineKeyboardButton("Continuar", callback_data='continuar')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # Verificar si el usuario ya ha visto el mensaje de bienvenida
    if not context.user_data.get('bienvenida_mostrada', False):
        explanation = (
            "¡ONGI ETORRI! esto es AstroCypher Bot! 🚀\n\n"
            "AstroCypher Bot es tu asistente de criptografía que permite cifrar y descifrar mensajes de manera segura utilizando el algoritmo RSA.\n\n"
        )
        await update.message.reply_text(explanation, reply_markup=reply_markup)
        context.user_data['bienvenida_mostrada'] = True
    else:
        await update.message.reply_text("Bienvenido de nuevo a AstroCypher Bot!", reply_markup=reply_markup)

    return CONTINUAR

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == 'set_clave':
        await query.edit_message_text(text="Por favor, introduce tu clave (número entre 1 y 25):")
        return SET_CLAVE
    elif query.data == 'cifrar':
        await query.edit_message_text(text="Por favor, introduce el alias del destinatario:")
        return CIFRAR_ALIAS
    elif query.data == 'descifrar':
        await query.edit_message_text(text="Por favor, introduce el mensaje cifrado:")
        return DESCIFRAR_MENSAJE
    elif query.data == 'listar_mensajes':
        await listar_mensajes(update, context)
    elif query.data == 'listar_claves':
        await listar_claves(update, context)
    elif query.data == 'eliminar_clave':
        await eliminar_clave(update, context)
    elif query.data == 'ver_mi_clave':
        await ver_mi_clave(update, context)
    elif query.data == 'eliminar_mensajes':
        await eliminar_mensajes(update, context)
    elif query.data == 'enviar_mensaje':
        return ENVIAR_MENSAJE
    elif query.data == 'seleccionar_contacto':
        await seleccionar_contacto(update, context)
        return SELECCIONAR_CONTACTO
    elif query.data == 'continuar':
        await continuar(update, context)
    return CONTINUAR

async def seleccionar_contacto(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT alias FROM usuarios')
        contactos = c.fetchall()
        conn.close()
        
        if not contactos:
            await update.callback_query.message.reply_text("No hay contactos disponibles.")
            return CONTINUAR
        
        # Crear botones para cada contacto
        botones = [[InlineKeyboardButton(contacto[0], callback_data=contacto[0])] for contacto in contactos]
        teclado = InlineKeyboardMarkup(botones)
        
        await update.callback_query.message.reply_text("Selecciona un contacto:", reply_markup=teclado)
        return SELECCIONAR_CONTACTO
    except sqlite3.DatabaseError as e:
        logging.error(f"Error al obtener los contactos: {e}")
        await update.callback_query.message.reply_text("Ocurrió un error al obtener los contactos.")
        return CONTINUAR

async def contacto_seleccionado(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    context.user_data['contacto'] = query.data
    await query.edit_message_text(text=f"Has seleccionado: {query.data}")
    
    # Preguntar por el mensaje a cifrar
    await query.message.reply_text("Introduce el mensaje que deseas cifrar:")
    return CIFRAR_MENSAJE

async def cifrar_mensaje_y_enviar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    alias = context.user_data['contacto']  # Usar el alias del contacto seleccionado
    mensaje = update.message.text
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT clave_publica, chat_id FROM usuarios WHERE alias = ?', (alias,))
        row = c.fetchone()
        if row is None:
            await update.message.reply_text("El usuario no ha establecido una clave pública.")
            conn.close()
            return CONTINUAR
        public_key_pem, chat_id = row
        public_key = serialization.load_pem_public_key(public_key_pem)
        mensaje_cifrado = cifrar_mensaje_rsa(mensaje, public_key)
        mensaje_cifrado_b64 = base64.b64encode(mensaje_cifrado).decode('utf-8')
        context.user_data['mensaje_cifrado'] = mensaje_cifrado_b64

        # Enviar el mensaje cifrado automáticamente
        await context.bot.send_message(chat_id=chat_id, text=f"Tienes un nuevo mensaje cifrado de {update.effective_user.username}: {mensaje_cifrado_b64}")
        await update.message.reply_text(f"Mensaje cifrado enviado a {alias}.")

        # Insertar el mensaje cifrado en la tabla mensajes como enviado
        c.execute('INSERT INTO mensajes (user_id, mensaje_cifrado, tipo) VALUES (?, ?, ?)', (update.message.from_user.id, mensaje_cifrado_b64, 'enviado'))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error al cifrar el mensaje: {e}")
        await update.message.reply_text("Ocurrió un error al cifrar el mensaje.")
    return await start(update, context)

# Modificar la función set_clave para almacenar el chat_id
async def set_clave(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        clave = int(update.message.text)
    except ValueError:
        await update.message.reply_text("La clave debe ser un número entero. Por favor, introduce tu clave nuevamente:")
        return SET_CLAVE

    if clave < 1 or clave > 25:
        await update.message.reply_text("La clave debe estar entre 1 y 25. Por favor, introduce tu clave nuevamente:")
        return SET_CLAVE

    user_id = update.message.from_user.id
    alias = update.message.from_user.username  # Obtener el nombre de usuario de Telegram
    chat_id = update.message.chat_id  # Obtener el chat_id del usuario
    if not alias:
        await update.message.reply_text("No tienes un nombre de usuario de Telegram. Por favor, establece uno en tu configuración de Telegram.")
        return CONTINUAR

    try:
        private_key, public_key = generar_claves()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except cryptography.exceptions.InvalidKey as e:
        logging.error(f"Error al generar las claves: {e}")
        await update.message.reply_text("Ocurrió un error al generar las claves.")
        return CONTINUAR

    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO usuarios (id, alias, clave_publica, clave_privada, chat_id) 
            VALUES (?, ?, ?, ?, ?) 
            ON CONFLICT(id) DO UPDATE SET 
                alias=excluded.alias, 
                clave_publica=excluded.clave_publica, 
                clave_privada=excluded.clave_privada,
                chat_id=excluded.chat_id
        ''', (user_id, alias, public_key_pem, private_key_pem, chat_id))
        conn.commit()
        conn.close()
        await update.message.reply_text(f"Clave pública y privada establecidas para el alias {alias}.")
    except sqlite3.DatabaseError as e:
        logging.error(f"Error al interactuar con la base de datos: {e}")
        await update.message.reply_text("Ocurrió un error al interactuar con la base de datos.")
    except Exception as e:
        logging.error(f"Error inesperado: {e}")
        await update.message.reply_text("Ocurrió un error inesperado al establecer la clave.")
    return await start(update, context)

async def cifrar_alias(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    context.user_data['cifrar_alias'] = query.message.text
    await query.message.reply_text("Por favor, introduce el mensaje que deseas cifrar:")
    return CIFRAR_MENSAJE

async def cifrar_mensaje(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mensaje = update.message.text
    try:
        # Generar claves temporales para cifrar el mensaje
        private_key, public_key = generar_claves()
        mensaje_cifrado = cifrar_mensaje_rsa(mensaje, public_key)
        mensaje_cifrado_b64 = base64.b64encode(mensaje_cifrado).decode('utf-8')
        context.user_data['mensaje_cifrado'] = mensaje_cifrado_b64

        # Mostrar el mensaje cifrado al usuario
        await update.message.reply_text(f"Mensaje cifrado:\n{mensaje_cifrado_b64}")
    except Exception as e:
        logging.error(f"Error al cifrar el mensaje: {e}")
        await update.message.reply_text("Ocurrió un error al cifrar el mensaje.")
    return CONTINUAR

async def descifrar_mensaje(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mensaje_cifrado = update.message.text
    user_id = update.message.from_user.id
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT clave_privada FROM usuarios WHERE id = ?', (user_id,))
        row = c.fetchone()
        if row is None:
            await update.message.reply_text("No tienes una clave privada establecida. Usa /clave <alias> <número>")
            conn.close()
            return CONTINUAR
        private_key_pem = row[0]
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        mensaje_descifrado = descifrar_mensaje_rsa(base64.b64decode(mensaje_cifrado), private_key)
        conn.close()
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(f"Mensaje descifrado: {mensaje_descifrado}", reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al descifrar el mensaje: {e}")
        await update.message.reply_text("Ocurrió un error al descifrar el mensaje.")
    return await start(update, context)

# Modificar la función enviar_mensaje para enviar una notificación al destinatario
async def enviar_mensaje(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    mensaje_cifrado_b64 = context.user_data.get('mensaje_cifrado')
    if not mensaje_cifrado_b64:
        await query.edit_message_text("No hay mensaje cifrado para enviar.")
        return CONTINUAR
    
    alias = context.user_data['contacto']
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT id, chat_id FROM usuarios WHERE alias = ?', (alias,))
        row = c.fetchone()
        if row is None:
            await query.edit_message_text("El usuario no está registrado.")
            conn.close()
            return CONTINUAR
        user_id, chat_id = row
        await context.bot.send_message(chat_id=chat_id, text=f"Tienes un nuevo mensaje cifrado de {update.effective_user.username}: {mensaje_cifrado_b64}")
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"Mensaje cifrado enviado a {alias}.", reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al enviar el mensaje: {e}")
        await query.edit_message_text("Ocurrió un error al enviar el mensaje.")
    return CONTINUAR

async def enviar_mensaje_final(update: Update, context: ContextTypes.DEFAULT_TYPE):
    alias = context.user_data.get('enviar_alias')
    if not alias:
        await update.message.reply_text("No se ha especificado un alias para enviar el mensaje.")
        return CONTINUAR
    mensaje = update.message.text
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT clave_publica FROM usuarios WHERE alias = ?', (alias,))
        row = c.fetchone()
        if row is None:
            await update.message.reply_text("El usuario no ha establecido una clave pública.")
            conn.close()
            return CONTINUAR
        public_key_pem = row[0]
        public_key = serialization.load_pem_public_key(public_key_pem)
        mensaje_cifrado = cifrar_mensaje_rsa(mensaje, public_key)
        mensaje_cifrado_b64 = base64.b64encode(mensaje_cifrado).decode('utf-8')
        await update.message.reply_text(f"\n{mensaje_cifrado_b64}")
    except Exception as e:
        logging.error(f"Error al enviar el mensaje: {e}")
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        mensajes_text = f"Error al enviar el mensaje: {e}"
        await update.callback_query.edit_message_text(mensajes_text, reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al listar los mensajes: {e}")
        await update.callback_query.edit_message_text("Ocurrió un error al listar los mensajes.")
    return await start(update, context)

async def listar_mensajes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT mensaje_cifrado, tipo FROM mensajes WHERE user_id = ?', (user_id,))
        rows = c.fetchall()
        conn.close()
        if not rows:
            await query.edit_message_text("No tienes mensajes cifrados.")
            return await start(query, context)
        mensajes_text = "Mensajes cifrados:\n"
        for row in rows:
            mensaje_cifrado_b64, tipo = row
            mensajes_text += f"{tipo.capitalize()}: {mensaje_cifrado_b64}\n"
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(mensajes_text, reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al listar los mensajes: {e}")
        await query.edit_message_text("Ocurrió un error al listar los mensajes.")
    return await start(query, context)

async def listar_claves(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT alias, clave_publica FROM usuarios')
        rows = c.fetchall()
        conn.close()
        if not rows:
            await query.edit_message_text("No hay claves públicas registradas.")
            return await start(query, context)
        claves_text = "Claves públicas registradas:\n"
        for row in rows:
            alias, clave_publica = row
            claves_text += f"Alias: {alias}, Clave pública: {clave_publica.decode()}\n"
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(claves_text, reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al listar las claves: {e}")
        await query.edit_message_text("Ocurrió un error al listar las claves.")
    return await start(query, context)

async def ver_mi_clave(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('SELECT alias, clave_publica FROM usuarios WHERE id = ?', (user_id,))
        row = c.fetchone()
        conn.close()
        if row is None:
            await query.edit_message_text("No tienes una clave pública establecida.")
            return await start(query, context)
        alias, clave_publica = row
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"Tu alias es {alias} y tu clave pública es:\n{clave_publica.decode()}", reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al obtener la clave: {e}")
        await query.edit_message_text("Ocurrió un error al obtener tu clave.")
    return await start(query, context)

async def eliminar_clave(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('DELETE FROM usuarios WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Tu clave ha sido eliminada.", reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al eliminar la clave: {e}")
        await query.edit_message_text("Ocurrió un error al eliminar la clave.")
    return await start(query, context)

async def eliminar_mensajes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    try:
        conn = sqlite3.connect('astrocypher.db')
        c = conn.cursor()
        c.execute('DELETE FROM mensajes WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        keyboard = [[InlineKeyboardButton("Continuar", callback_data='continuar')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Todos tus mensajes cifrados han sido eliminados.", reply_markup=reply_markup)
    except Exception as e:
        logging.error(f"Error al eliminar los mensajes: {e}")
        await query.edit_message_text("Ocurrió un error al eliminar los mensajes.")
    return await start(query, context)

async def continuar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.message.reply_text("Continuando...")
    return CONTINUAR

# Modificar el ConversationHandler para incluir la nueva etapa
conv_handler = ConversationHandler(
    entry_points=[CommandHandler('start', start)],
    states={
        SET_CLAVE: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_clave)],
        CIFRAR_ALIAS: [MessageHandler(filters.TEXT & ~filters.COMMAND, cifrar_alias)],
        CIFRAR_MENSAJE: [MessageHandler(filters.TEXT & ~filters.COMMAND, cifrar_mensaje_y_enviar)],
        DESCIFRAR_MENSAJE: [MessageHandler(filters.TEXT & ~filters.COMMAND, descifrar_mensaje)],
        ENVIAR_MENSAJE: [CallbackQueryHandler(enviar_mensaje)],
        CONTINUAR: [CallbackQueryHandler(button)],
        SELECCIONAR_CONTACTO: [CallbackQueryHandler(contacto_seleccionado)]
    },
    fallbacks=[CommandHandler('start', start)],
    per_chat=True  # Asegurar que se maneje cada chat
)

# Crear una instancia de la aplicación del bot
app = Application.builder().token(TOKEN).build()

# Añadir el ConversationHandler a la aplicación
app.add_handler(conv_handler)

# Iniciar la aplicación del bot
app.run_polling()


