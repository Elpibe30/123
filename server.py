import os
import re
import time
import uuid
import secrets
import hashlib
import datetime
from functools import wraps
from collections import defaultdict

import stripe
import sqlite3
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

# ========== CONFIGURACIÓN ==========
# 🔐 Claves desde variables de entorno (SEGURO)
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
STRIPE_PAYMENT_LINK = os.environ.get('STRIPE_PAYMENT_LINK', 'https://buy.stripe.com/test_eVqfZicUkbd51Ndf5C18c00')

stripe.api_key = STRIPE_SECRET_KEY

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# 🌐 CORS RESTRINGIDO - Solo dominios autorizados
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5000,http://localhost:3000')
CORS(app, origins=ALLOWED_ORIGINS.split(','))

# 🔧 Modo DEBUG desactivado para producción
DEBUG_MODE = os.environ.get('DEBUG_MODE', 'False').lower() == 'true'

DB_PATH = 'productos.db'

# Rate limiting
peticiones_ip = defaultdict(list)
LIMITE_PETICIONES = 100
VENTANA_TIEMPO = 60
BLOQUEO_IP_TIEMPO = 300
ips_bloqueadas = {}

# ========== FUNCIONES DE SEGURIDAD ==========

def hash_password(password):
    """Hash de contraseña con salt usando PBKDF2"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return f"{salt}${password_hash}"

def verify_password(password, stored):
    """Verificar contraseña con salt"""
    try:
        salt, hash_value = stored.split('$')
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return new_hash == hash_value
    except:
        return False

def verificar_rate_limit_ip(ip_address):
    ahora = time.time()
    
    if ip_address in ips_bloqueadas:
        if ahora < ips_bloqueadas[ip_address]:
            return False, ips_bloqueadas[ip_address]
        else:
            del ips_bloqueadas[ip_address]
            peticiones_ip[ip_address] = []
    
    peticiones_ip[ip_address] = [ts for ts in peticiones_ip[ip_address] if ahora - ts < VENTANA_TIEMPO]
    
    if len(peticiones_ip[ip_address]) >= LIMITE_PETICIONES:
        tiempo_bloqueo = ahora + BLOQUEO_IP_TIEMPO
        ips_bloqueadas[ip_address] = tiempo_bloqueo
        return False, tiempo_bloqueo
    
    peticiones_ip[ip_address].append(ahora)
    return True, None

def validar_requisitos_password(password):
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe tener al menos una letra mayúscula"
    if not re.search(r'[0-9]', password):
        return False, "La contraseña debe tener al menos un número"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "La contraseña debe tener al menos un símbolo"
    return True, "Válida"

def registrar_log_seguridad(user_id, accion, ip_address, detalles=""):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_logs (user_id, accion, ip_address, detalles, fecha)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, accion, ip_address, detalles[:500], datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

def limpiar_numero(valor):
    if pd.isna(valor):
        return 0
    if isinstance(valor, (int, float)):
        return float(valor)
    if isinstance(valor, str):
        valor = valor.replace(',', '').replace(' ', '').strip()
        valor = re.sub(r'[Bb][Ss]', '', valor).strip()
        valor = re.sub(r'[^\d.-]', '', valor)
        try:
            return float(valor)
        except:
            return 0
    return 0

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Tabla de usuarios
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        salt TEXT,
        nombre TEXT,
        fecha_registro TEXT,
        es_admin INTEGER DEFAULT 0,
        es_vip INTEGER DEFAULT 0,
        es_premium INTEGER DEFAULT 0,
        premium_end TEXT,
        trial_end TEXT,
        device_id TEXT,
        login_intentos INTEGER DEFAULT 0,
        bloqueado_hasta TEXT,
        stripe_customer_id TEXT,
        last_password_change TEXT
    )''')
    
    # Tabla de sesiones
    cursor.execute('''CREATE TABLE IF NOT EXISTS sesiones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        fecha_creacion TEXT,
        ip_address TEXT,
        user_agent TEXT
    )''')
    
    # Tabla de credenciales guardadas
    cursor.execute('''CREATE TABLE IF NOT EXISTS credenciales_guardadas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT,
        nombre TEXT,
        fecha_guardado TEXT,
        FOREIGN KEY (user_id) REFERENCES usuarios(id)
    )''')
    
    # Tabla de intentos por dispositivo
    cursor.execute('''CREATE TABLE IF NOT EXISTS intentos_dispositivo (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE,
        intentos INTEGER DEFAULT 0,
        bloqueado_hasta TEXT
    )''')
    
    # Tabla de items
    cursor.execute('''CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        texto TEXT,
        tipo TEXT,
        precio REAL,
        unidad TEXT,
        ciudad TEXT,
        direccion TEXT,
        contacto TEXT,
        producto_servicio TEXT,
        info_extra TEXT
    )''')
    
    # Tabla de búsquedas
    cursor.execute('''CREATE TABLE IF NOT EXISTS busquedas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        termino TEXT,
        fecha TEXT,
        user_id INTEGER
    )''')
    
    # Tabla de registros por dispositivo
    cursor.execute('''CREATE TABLE IF NOT EXISTS registros_dispositivo (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE,
        cantidad_registros INTEGER DEFAULT 0
    )''')
    
    # Tabla de logs de seguridad
    cursor.execute('''CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        accion TEXT,
        ip_address TEXT,
        detalles TEXT,
        fecha TEXT
    )''')
    
    # Admin por defecto
    cursor.execute("SELECT * FROM usuarios WHERE email = 'admin@pricewise.com'")
    if not cursor.fetchone():
        admin_pass_hash = hash_password("AdminPriceWise2024")
        today = datetime.date.today().isoformat()
        now = datetime.datetime.now().isoformat()
        cursor.execute('''INSERT INTO usuarios 
            (email, password_hash, nombre, fecha_registro, es_admin, es_vip, es_premium, trial_end, last_password_change) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            ("admin@pricewise.com", admin_pass_hash, "Administrador", today, 1, 0, 0, "ilimitado", now))
        print("✅ Admin creado")
    
    conn.commit()
    conn.close()
    print("✅ Base de datos inicializada correctamente")

def tiene_acceso_total(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT es_admin, es_vip, es_premium, premium_end, trial_end 
        FROM usuarios WHERE id = ?
    """, (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return False, "sin_acceso"
    
    if user['es_admin'] == 1 or user['es_vip'] == 1:
        return True, "admin_vip"
    if user['es_premium'] == 1 and user['premium_end']:
        try:
            if datetime.datetime.now() < datetime.datetime.fromisoformat(user['premium_end']):
                return True, "premium"
        except:
            pass
    if user['trial_end'] and user['trial_end'] != 'ilimitado':
        try:
            if datetime.datetime.now() < datetime.datetime.fromisoformat(user['trial_end']):
                return True, "trial"
        except:
            pass
    return False, "demo"

def verificar_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token requerido'}), 401
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM sesiones WHERE token = ?", (token,))
        session_data = cursor.fetchone()
        conn.close()
        if not session_data:
            return jsonify({'error': 'Token inválido'}), 401
        request.user_id = session_data['user_id']
        return f(*args, **kwargs)
    return decorated

def verificar_bloqueo_dispositivo(device_id, email):
    if email == 'admin@pricewise.com':
        return False, None
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT intentos, bloqueado_hasta FROM intentos_dispositivo WHERE device_id = ?", (device_id,))
    registro = cursor.fetchone()
    conn.close()
    
    if registro and registro['bloqueado_hasta']:
        try:
            bloqueado_hasta = datetime.datetime.fromisoformat(registro['bloqueado_hasta'])
            if datetime.datetime.now() < bloqueado_hasta:
                return True, registro['bloqueado_hasta']
        except:
            pass
    return False, None

def registrar_intento_fallido_dispositivo(device_id, email):
    if email == 'admin@pricewise.com':
        return
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT intentos FROM intentos_dispositivo WHERE device_id = ?", (device_id,))
    registro = cursor.fetchone()
    
    if registro:
        nuevos_intentos = registro['intentos'] + 1
        if nuevos_intentos >= 5:
            bloqueado_hasta = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
            cursor.execute("UPDATE intentos_dispositivo SET intentos = ?, bloqueado_hasta = ? WHERE device_id = ?",
                          (nuevos_intentos, bloqueado_hasta, device_id))
        else:
            cursor.execute("UPDATE intentos_dispositivo SET intentos = ? WHERE device_id = ?", (nuevos_intentos, device_id))
    else:
        cursor.execute("INSERT INTO intentos_dispositivo (device_id, intentos) VALUES (?, 1)", (device_id,))
    
    conn.commit()
    conn.close()

def resetear_intentos_dispositivo(device_id, email):
    if email == 'admin@pricewise.com':
        return
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM intentos_dispositivo WHERE device_id = ?", (device_id,))
    conn.commit()
    conn.close()

def verificar_bloqueo_usuario(email):
    if email == 'admin@pricewise.com':
        return False, None
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT login_intentos, bloqueado_hasta FROM usuarios WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and user['bloqueado_hasta']:
        try:
            bloqueado_hasta = datetime.datetime.fromisoformat(user['bloqueado_hasta'])
            if datetime.datetime.now() < bloqueado_hasta:
                return True, user['bloqueado_hasta']
        except:
            pass
    return False, None

def registrar_intento_fallido_usuario(email):
    if email == 'admin@pricewise.com':
        return
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT login_intentos FROM usuarios WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if user:
        nuevos_intentos = user['login_intentos'] + 1
        if nuevos_intentos >= 5:
            bloqueado_hasta = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
            cursor.execute("UPDATE usuarios SET login_intentos = ?, bloqueado_hasta = ? WHERE email = ?",
                          (nuevos_intentos, bloqueado_hasta, email))
        else:
            cursor.execute("UPDATE usuarios SET login_intentos = ? WHERE email = ?", (nuevos_intentos, email))
    else:
        cursor.execute("INSERT INTO usuarios (email, login_intentos) VALUES (?, 1)", (email,))
    
    conn.commit()
    conn.close()

def resetear_intentos_usuario(email):
    if email == 'admin@pricewise.com':
        return
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET login_intentos = 0, bloqueado_hasta = NULL WHERE email = ?", (email,))
    conn.commit()
    conn.close()

def verificar_limite_registros(device_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT cantidad_registros FROM registros_dispositivo WHERE device_id = ?", (device_id,))
    registro = cursor.fetchone()
    conn.close()
    
    if registro and registro['cantidad_registros'] >= 3:
        return False, registro['cantidad_registros']
    return True, registro['cantidad_registros'] if registro else 0

def incrementar_registro_dispositivo(device_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO registros_dispositivo (device_id, cantidad_registros) VALUES (?, 1) ON CONFLICT(device_id) DO UPDATE SET cantidad_registros = cantidad_registros + 1", (device_id,))
    conn.commit()
    conn.close()

def decrementar_registro_dispositivo(device_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT cantidad_registros FROM registros_dispositivo WHERE device_id = ?", (device_id,))
    registro = cursor.fetchone()
    
    if registro and registro['cantidad_registros'] > 0:
        cursor.execute("UPDATE registros_dispositivo SET cantidad_registros = cantidad_registros - 1 WHERE device_id = ?", (device_id,))
    conn.commit()
    conn.close()

def es_email_valido(email):
    if email == 'admin@pricewise.com':
        return True
    return email.endswith('@gmail.com')

# ========== WEBHOOK DE STRIPE ==========

@app.route('/webhook', methods=['POST'])
def webhook_receiver():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 401
    
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_email = session.get('customer_details', {}).get('email')
        
        if customer_email:
            print(f"💳 Pago recibido de: {customer_email}")
            
            premium_end = (datetime.datetime.now() + datetime.timedelta(days=30)).isoformat()
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE usuarios 
                SET es_premium = 1, es_vip = 0, premium_end = ?, trial_end = ?
                WHERE email = ?
            """, (premium_end, premium_end, customer_email))
            
            if cursor.rowcount > 0:
                conn.commit()
                cursor.execute("DELETE FROM sesiones WHERE user_id IN (SELECT id FROM usuarios WHERE email = ?)", (customer_email,))
                conn.commit()
                print(f"✅ Usuario {customer_email} actualizado a Premium")
            else:
                print(f"⚠️ Usuario {customer_email} no encontrado")
            
            conn.close()
    
    return jsonify({'status': 'success'}), 200

# ========== RUTAS DE AUTENTICACIÓN ==========

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nombre = data.get('nombre')
    device_id = data.get('device_id')
    
    if not email or not password or not nombre:
        return jsonify({'error': 'Faltan datos'}), 400
    
    if not es_email_valido(email):
        return jsonify({'error': 'Solo se permiten cuentas de Gmail'}), 400
    
    valida, mensaje = validar_requisitos_password(password)
    if not valida:
        return jsonify({'error': mensaje}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Email ya registrado'}), 400
    
    if email != 'admin@pricewise.com':
        puede_registrar, cantidad = verificar_limite_registros(device_id)
        if not puede_registrar:
            conn.close()
            return jsonify({'error': f'Límite de 3 cuentas por dispositivo alcanzado'}), 400
    
    password_hash = hash_password(password)  # 🔐 Ahora con salt
    today = datetime.date.today().isoformat()
    trial_end = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    now = datetime.datetime.now().isoformat()
    
    cursor.execute('''INSERT INTO usuarios 
        (email, password_hash, nombre, fecha_registro, trial_end, device_id, es_vip, es_premium, es_admin, last_password_change) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (email, password_hash, nombre, today, trial_end, device_id, 0, 0, 0, now))
    
    conn.commit()
    conn.close()
    
    if email != 'admin@pricewise.com':
        incrementar_registro_dispositivo(device_id)
    
    registrar_log_seguridad(0, "📝 Nuevo registro", request.remote_addr, f"Nuevo usuario: {email}")
    
    return jsonify({'message': 'Registro exitoso. Tienes 30 días de prueba gratuita.'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    device_id = data.get('device_id')
    guardar_credencial = data.get('guardar_credencial', False)
    
    if not email or not password:
        return jsonify({'error': 'Faltan datos'}), 400
    
    if not es_email_valido(email):
        return jsonify({'error': 'Solo se permiten cuentas de Gmail'}), 400
    
    bloqueado_dispositivo, hasta_dispositivo = verificar_bloqueo_dispositivo(device_id, email)
    if bloqueado_dispositivo:
        return jsonify({'error': f'Demasiados intentos. Bloqueado hasta {hasta_dispositivo}'}), 401
    
    bloqueado_usuario, hasta_usuario = verificar_bloqueo_usuario(email)
    if bloqueado_usuario:
        return jsonify({'error': f'Demasiados intentos. Cuenta bloqueada hasta {hasta_usuario}'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, nombre, es_admin, es_vip, es_premium, premium_end, trial_end, password_hash
        FROM usuarios WHERE email = ?
    """, (email,))
    user = cursor.fetchone()
    
    if not user or not verify_password(password, user['password_hash']):  # 🔐 Verificación con salt
        conn.close()
        registrar_intento_fallido_dispositivo(device_id, email)
        registrar_intento_fallido_usuario(email)
        registrar_log_seguridad(0, "❌ Intento login FALLIDO", request.remote_addr, f"Email: {email}")
        return jsonify({'error': 'Credenciales incorrectas'}), 401
    
    resetear_intentos_dispositivo(device_id, email)
    resetear_intentos_usuario(email)
    
    # 🚪 CERRAR SESIÓN EN OTROS DISPOSITIVOS (lo que ya tenías)
    cursor.execute("DELETE FROM sesiones WHERE user_id = ?", (user['id'],))
    
    token = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    cursor.execute("INSERT INTO sesiones (user_id, token, fecha_creacion, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
                   (user['id'], token, now, ip_address, user_agent))
    
    if guardar_credencial:
        cursor.execute("DELETE FROM credenciales_guardadas WHERE user_id = ?", (user['id'],))
        cursor.execute('''INSERT INTO credenciales_guardadas 
            (user_id, email, nombre, fecha_guardado) 
            VALUES (?, ?, ?, ?)''',
            (user['id'], email, user['nombre'], now))
    
    conn.commit()
    conn.close()
    
    registrar_log_seguridad(user['id'], "✅ Login exitoso", ip_address, f"Dispositivo: {device_id[:10]}...")
    
    tiene_acceso, tipo_acceso = tiene_acceso_total(user['id'])
    
    return jsonify({
        'token': token,
        'user_id': user['id'],
        'nombre': user['nombre'],
        'es_admin': bool(user['es_admin']),
        'es_vip': bool(user['es_vip']),
        'es_premium': bool(user['es_premium']),
        'premium_end': user['premium_end'],
        'trial_end': user['trial_end'],
        'tiene_acceso': tiene_acceso,
        'tipo_acceso': tipo_acceso
    })

@app.route('/api/credenciales_guardadas', methods=['GET'])
@verificar_token
def obtener_credenciales():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM credenciales_guardadas WHERE user_id = ?", (request.user_id,))
    credenciales = cursor.fetchall()
    conn.close()
    return jsonify([dict(c) for c in credenciales])

# ========== RUTAS DE ADMIN ==========

@app.route('/api/admin/usuarios', methods=['GET'])
@verificar_token
def admin_usuarios():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    user = cursor.fetchone()
    
    if not user or not user['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    # No devolvemos password_hash por seguridad
    cursor.execute("""
        SELECT id, email, nombre, es_admin, es_vip, es_premium, premium_end, trial_end, device_id
        FROM usuarios ORDER BY id DESC
    """)
    usuarios = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in usuarios])

@app.route('/api/admin/buscar_usuario', methods=['GET'])
@verificar_token
def admin_buscar_usuario():
    termino = request.args.get('q', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    user = cursor.fetchone()
    
    if not user or not user['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    cursor.execute("""
        SELECT id, email, nombre, es_admin, es_vip, es_premium, premium_end, trial_end, device_id
        FROM usuarios 
        WHERE email LIKE ? OR nombre LIKE ?
        LIMIT 1
    """, (f"%{termino}%", f"%{termino}%"))
    
    usuario = cursor.fetchone()
    conn.close()
    
    if not usuario:
        return jsonify({}), 200
    
    return jsonify(dict(usuario))

@app.route('/api/admin/toggle_vip', methods=['POST'])
@verificar_token
def admin_toggle_vip():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    admin = cursor.fetchone()
    
    if not admin or not admin['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    cursor.execute("SELECT es_vip, email, es_premium FROM usuarios WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if user['email'] == 'admin@pricewise.com':
        conn.close()
        return jsonify({'error': 'No puedes modificar el VIP del administrador principal'}), 400
    
    nuevo_estado = 1 if user['es_vip'] == 0 else 0
    
    if nuevo_estado == 1:
        cursor.execute("UPDATE usuarios SET es_vip = 1, es_premium = 0, es_admin = 0, trial_end = 'ilimitado', premium_end = NULL WHERE id = ?", (user_id,))
        mensaje = '✅ Usuario convertido a VIP (acceso ILIMITADO - no paga)'
        accion = "⭐ Convertir a VIP"
    else:
        trial_end = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        cursor.execute("UPDATE usuarios SET es_vip = 0, trial_end = ? WHERE id = ?", (trial_end, user_id))
        mensaje = '❌ Usuario removido de VIP (vuelve a prueba de 30 días)'
        accion = "❌ Remover VIP"
    
    conn.commit()
    conn.close()
    
    registrar_log_seguridad(request.user_id, accion, request.remote_addr, f"Usuario {user_id} -> VIP={nuevo_estado}")
    
    return jsonify({'message': mensaje})

@app.route('/api/admin/toggle_premium', methods=['POST'])
@verificar_token
def admin_toggle_premium():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    admin = cursor.fetchone()
    
    if not admin or not admin['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    cursor.execute("SELECT es_premium, email, es_vip FROM usuarios WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if user['email'] == 'admin@pricewise.com':
        conn.close()
        return jsonify({'error': 'No puedes modificar el Premium del administrador principal'}), 400
    
    if user['es_premium'] == 1:
        trial_end = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        cursor.execute("UPDATE usuarios SET es_premium = 0, premium_end = NULL, trial_end = ? WHERE id = ?", (trial_end, user_id))
        mensaje = '❌ Usuario removido de Premium (vuelve a prueba de 30 días)'
        accion = "❌ Remover Premium"
    else:
        premium_end = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        cursor.execute("UPDATE usuarios SET es_premium = 1, premium_end = ?, es_vip = 0, trial_end = ? WHERE id = ?", 
                      (premium_end, premium_end, user_id))
        mensaje = '✅ Usuario convertido a Premium (suscripción por 30 días - $6.50/mes)'
        accion = "💎 Convertir a Premium"
    
    conn.commit()
    conn.close()
    
    registrar_log_seguridad(request.user_id, accion, request.remote_addr, f"Usuario {user_id}")
    
    return jsonify({'message': mensaje})

@app.route('/api/admin/forzar_pago', methods=['POST'])
@verificar_token
def admin_forzar_pago():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    admin = cursor.fetchone()
    
    if not admin or not admin['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    cursor.execute("SELECT email, es_vip FROM usuarios WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if user['email'] == 'admin@pricewise.com':
        conn.close()
        return jsonify({'error': 'No puedes forzar pago al administrador principal'}), 400
    
    if user['es_vip'] == 1:
        conn.close()
        return jsonify({'error': 'Usuario VIP tiene acceso ilimitado'}), 400
    
    fecha_expirada = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
    
    cursor.execute("""
        UPDATE usuarios 
        SET es_premium = 0, premium_end = NULL, trial_end = ?
        WHERE id = ?
    """, (fecha_expirada, user_id))
    
    cursor.execute("DELETE FROM sesiones WHERE user_id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    registrar_log_seguridad(request.user_id, "💳 Forzar pago", request.remote_addr, f"Usuario {user_id}")
    
    return jsonify({'message': 'Usuario forzado a pagar exitosamente'})

@app.route('/api/admin/eliminar_usuario', methods=['POST'])
@verificar_token
def admin_eliminar_usuario():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    admin = cursor.fetchone()
    
    if not admin or not admin['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    if user_id == request.user_id:
        conn.close()
        return jsonify({'error': 'No puedes eliminarte a ti mismo'}), 400
    
    cursor.execute("SELECT email, device_id FROM usuarios WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if user['email'] == 'admin@pricewise.com':
        conn.close()
        return jsonify({'error': 'No puedes eliminar al administrador principal'}), 400
    
    device_id = user['device_id']
    
    registrar_log_seguridad(request.user_id, "🗑️ Eliminar usuario", request.remote_addr, f"Usuario eliminado: {user['email']}")
    
    cursor.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
    cursor.execute("DELETE FROM sesiones WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM credenciales_guardadas WHERE user_id = ?", (user_id,))
    
    if device_id:
        decrementar_registro_dispositivo(device_id)
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Usuario eliminado correctamente'})

@app.route('/api/admin/agregar_usuario', methods=['POST'])
@verificar_token
def admin_agregar_usuario():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nombre = data.get('nombre')
    es_admin = data.get('es_admin', False)
    es_vip = data.get('es_vip', False)
    es_premium = data.get('es_premium', False)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    admin = cursor.fetchone()
    
    if not admin or not admin['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    if not email or not password or not nombre:
        conn.close()
        return jsonify({'error': 'Faltan datos'}), 400
    
    if email != 'admin@pricewise.com' and not email.endswith('@gmail.com'):
        conn.close()
        return jsonify({'error': 'Solo se permiten cuentas de Gmail'}), 400
    
    valida, mensaje = validar_requisitos_password(password)
    if not valida:
        conn.close()
        return jsonify({'error': mensaje}), 400
    
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Email ya registrado'}), 400
    
    password_hash = hash_password(password)  # 🔐 Ahora con salt
    today = datetime.date.today().isoformat()
    trial_end = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    premium_end = (datetime.date.today() + datetime.timedelta(days=30)).isoformat() if es_premium else None
    now = datetime.datetime.now().isoformat()
    
    if es_admin or es_vip:
        trial_end_final = "ilimitado"
    elif es_premium:
        trial_end_final = premium_end
    else:
        trial_end_final = trial_end
    
    cursor.execute('''INSERT INTO usuarios 
        (email, password_hash, nombre, fecha_registro, es_admin, es_vip, es_premium, trial_end, premium_end, last_password_change) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (email, password_hash, nombre, today, 
         1 if es_admin else 0, 
         1 if es_vip else 0, 
         1 if es_premium else 0,
         trial_end_final,
         premium_end, now))
    
    conn.commit()
    conn.close()
    
    registrar_log_seguridad(request.user_id, "➕ Agregar usuario", request.remote_addr, f"Usuario creado: {email}")
    
    return jsonify({'message': 'Usuario agregado correctamente'})

@app.route('/api/admin/cambiar_password', methods=['POST'])
@verificar_token
def admin_cambiar_password():
    data = request.json
    user_id = data.get('user_id')
    nueva_password = data.get('nueva_password')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    admin = cursor.fetchone()
    
    if not admin or not admin['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    if not nueva_password:
        conn.close()
        return jsonify({'error': 'La contraseña es requerida'}), 400
    
    valida, mensaje = validar_requisitos_password(nueva_password)
    if not valida:
        conn.close()
        return jsonify({'error': mensaje}), 400
    
    password_hash = hash_password(nueva_password)  # 🔐 Ahora con salt
    now = datetime.datetime.now().isoformat()
    
    cursor.execute("UPDATE usuarios SET password_hash = ?, last_password_change = ? WHERE id = ?", (password_hash, now, user_id))
    cursor.execute("DELETE FROM sesiones WHERE user_id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    registrar_log_seguridad(request.user_id, "🔑 Admin cambio contraseña", request.remote_addr, f"Contraseña cambiada para usuario {user_id}")
    
    return jsonify({'message': 'Contraseña cambiada correctamente'})

# ========== RUTAS DE BÚSQUEDA ==========

@app.route('/api/buscar', methods=['GET'])
@verificar_token
def buscar():
    ip_address = request.remote_addr
    permitido, tiempo_bloqueo = verificar_rate_limit_ip(ip_address)
    
    if not permitido:
        tiempo_restante = int(tiempo_bloqueo - time.time())
        return jsonify({
            'error': f'🚫 Demasiadas peticiones. Bloqueado por {tiempo_restante} segundos.'
        }), 429
    
    termino = request.args.get('q', '').lower().strip()
    
    tiene_acceso, tipo_acceso = tiene_acceso_total(request.user_id)
    
    conn = get_db()
    cursor = conn.cursor()
    
    if not tiene_acceso:
        return jsonify({
            'sin_acceso': True,
            'tipo': 'demo',
            'mensaje': '⚠️ Tu periodo de prueba de 30 días ha expirado. Debes pagar $6.50/mes para seguir usando ICORP.'
        }), 403
    
    # SIN LÍMITE DE RESULTADOS - como pediste
    if termino:
        cursor.execute('''SELECT texto, tipo, precio, unidad, ciudad, direccion, contacto, producto_servicio, info_extra
                          FROM items 
                          WHERE LOWER(texto) LIKE LOWER(?) 
                             OR LOWER(ciudad) LIKE LOWER(?)
                             OR LOWER(direccion) LIKE LOWER(?)
                             OR LOWER(contacto) LIKE LOWER(?)
                             OR LOWER(producto_servicio) LIKE LOWER(?)
                             OR LOWER(info_extra) LIKE LOWER(?)
                          ORDER BY tipo DESC, texto ASC''', 
                       (f"%{termino}%", f"%{termino}%", f"%{termino}%", f"%{termino}%", f"%{termino}%", f"%{termino}%"))
    else:
        cursor.execute("SELECT texto, tipo, precio, unidad, ciudad, direccion, contacto, producto_servicio, info_extra FROM items ORDER BY tipo DESC, texto ASC")
    
    resultados = cursor.fetchall()
    conn.close()
    return jsonify([dict(r) for r in resultados])

@app.route('/api/sincronizar', methods=['POST'])
@verificar_token
def sincronizar():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    user = cursor.fetchone()
    
    if not user or not user['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No se envio archivo'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Archivo vacio'}), 400
    
    temp_path = 'temp_excel.xlsx'
    file.save(temp_path)
    
    try:
        df = pd.read_excel(temp_path, sheet_name=0)
        cursor.execute("DELETE FROM items")
        
        contador_productos = 0
        contador_empresas = 0
        
        DEPARTAMENTOS = ['LPZ', 'SCZ', 'CBBA', 'ORU', 'POT', 'TJA', 'BEN', 'PAN', 'CHO']
        PALABRAS_EMPRESA = ['SRL', 'LTDA', 'S.A.', 'CONSTRUCTORA', 'EMPRESA', 'IMPORTADORA',
                           'ACERMAX', 'SOBOCE', 'SIKA', 'CERABOL', 'DURALIT', 'MONOPOL',
                           'TICONAL', 'PLUSSTEEL', 'FERROTODO', 'MULTIACEROS', 'FABOCE',
                           'TEKTRON', 'ISOLCRUZ', 'MACCAFERRI', 'SANEAR', 'VALKURE',
                           'BOLIVIAN ELECTRIC', 'ELECTRIC', 'PLASTIFORTE', 'QUASAR', 'PRETENSA']
        
        inicio_empresas = None
        for idx, row in df.iterrows():
            for col in df.columns:
                valor = str(row[col]) if pd.notna(row[col]) else ""
                if "EMPRESAS" in valor.upper() or "PROVEEDORES" in valor.upper():
                    inicio_empresas = idx + 1
                    break
            if inicio_empresas:
                break
        
        if not inicio_empresas:
            inicio_empresas = 5270
        
        for idx, row in df.iterrows():
            valores_fila = []
            for col in df.columns:
                valor = str(row[col]) if pd.notna(row[col]) else ""
                if valor and valor != 'nan' and len(valor.strip()) > 1:
                    valores_fila.append(valor.strip())
            
            if not valores_fila:
                continue
            
            titulo = valores_fila[0]
            es_empresa = False
            
            for palabra in PALABRAS_EMPRESA:
                if palabra.upper() in titulo.upper():
                    es_empresa = True
                    break
            
            if idx >= inicio_empresas:
                es_empresa = True
            
            for valor in valores_fila:
                if '@' in valor or 'www.' in valor.lower() or 'tel' in valor.lower():
                    es_empresa = True
                    break
            
            if es_empresa:
                contador_empresas += 1
                ciudad = ""
                direccion = ""
                contacto = ""
                producto = ""
                
                for i, valor in enumerate(valores_fila):
                    if i == 0:
                        continue
                    
                    for depto in DEPARTAMENTOS:
                        if depto in valor.upper():
                            ciudad = depto
                            break
                    if 'LA PAZ' in valor.upper():
                        ciudad = 'LPZ'
                    
                    if 'calle' in valor.lower() or 'av' in valor.lower() or 'km' in valor.lower():
                        if not direccion:
                            direccion = valor
                        else:
                            direccion += " | " + valor
                    elif '@' in valor or 'www.' in valor.lower() or 'tel' in valor.lower() or '+' in valor:
                        if not contacto:
                            contacto = valor
                        else:
                            contacto += " | " + valor
                    else:
                        if not producto:
                            producto = valor
                        else:
                            producto += " | " + valor
                
                cursor.execute('''INSERT INTO items 
                    (texto, tipo, precio, unidad, ciudad, direccion, contacto, producto_servicio, info_extra) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (titulo[:200], 'empresa', 0, '', ciudad[:20], direccion[:500], contacto[:500], producto[:500], ''))
            else:
                contador_productos += 1
                precio = 0
                unidad = ""
                
                for valor in valores_fila:
                    num = limpiar_numero(valor)
                    if num > 0 and num < 100000:
                        if num > precio:
                            precio = num
                    if len(valor) < 10 and any(x in valor.lower() for x in ['m2', 'm3', 'kg', 'pza', 'unidad', 'm', 'l', 'hr']):
                        unidad = valor
                
                cursor.execute('''INSERT INTO items 
                    (texto, tipo, precio, unidad, ciudad, direccion, contacto, producto_servicio, info_extra) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (titulo[:200], 'producto', precio, unidad[:20], '', '', '', '', ''))
        
        conn.commit()
        os.remove(temp_path)
        conn.close()
        
        registrar_log_seguridad(request.user_id, "📤 Sincronizar Excel", request.remote_addr, f"{contador_productos} productos, {contador_empresas} empresas")
        
        return jsonify({'message': f'{contador_productos} productos y {contador_empresas} empresas sincronizados'})
        
    except Exception as e:
        conn.close()
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': str(e)}), 500

@app.route('/api/version', methods=['GET'])
def version():
    return jsonify({'status': 'ok', 'message': 'ICORP Server'})

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("ICORP - SERVIDOR")
    print("http://localhost:5000")
    print("=" * 50)
    # Debug solo si se especifica
    debug_mode = os.environ.get('DEBUG_MODE', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)