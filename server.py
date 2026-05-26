from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import datetime
import hashlib
import pandas as pd
import os
import uuid
from functools import wraps

app = Flask(__name__)
CORS(app)

DB_PATH = 'productos.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        nombre TEXT,
        fecha_registro TEXT,
        es_admin INTEGER DEFAULT 0,
        trial_end TEXT,
        subscription_end TEXT,
        device_id TEXT
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        texto TEXT,
        tipo TEXT,
        precio REAL,
        unidad TEXT,
        fila_original TEXT
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS sesiones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        fecha_creacion TEXT
    )''')
    
    cursor.execute("SELECT * FROM usuarios WHERE email = 'admin@tuapp.com'")
    if not cursor.fetchone():
        admin_pass = hashlib.sha256("admin123".encode()).hexdigest()
        today = datetime.date.today().isoformat()
        cursor.execute('''INSERT INTO usuarios 
            (email, password, nombre, fecha_registro, es_admin, trial_end, subscription_end) 
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            ("admin@tuapp.com", admin_pass, "Admin", today, 1, today, today))
    
    conn.commit()
    conn.close()
    print("✅ Base de datos inicializada")

def verificar_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token requerido'}), 401
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM sesiones WHERE token = ?", (token,))
        session = cursor.fetchone()
        conn.close()
        
        if not session:
            return jsonify({'error': 'Token inválido'}), 401
        
        request.user_id = session['user_id']
        return f(*args, **kwargs)
    return decorated

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nombre = data.get('nombre')
    device_id = data.get('device_id')
    
    if not email or not password or not nombre:
        return jsonify({'error': 'Faltan datos'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Email ya registrado'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    today = datetime.date.today().isoformat()
    trial_end = (datetime.date.today() + datetime.timedelta(days=45)).isoformat()
    
    cursor.execute('''INSERT INTO usuarios 
        (email, password, nombre, fecha_registro, trial_end, device_id) 
        VALUES (?, ?, ?, ?, ?, ?)''',
        (email, password_hash, nombre, today, trial_end, device_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Registro exitoso', 'trial_end': trial_end}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    device_id = data.get('device_id')
    
    if not email or not password:
        return jsonify({'error': 'Faltan datos'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, nombre, es_admin, trial_end, subscription_end FROM usuarios WHERE email = ? AND password = ?", 
                   (email, password_hash))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Credenciales incorrectas'}), 401
    
    token = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    cursor.execute("INSERT INTO sesiones (user_id, token, fecha_creacion) VALUES (?, ?, ?)",
                   (user['id'], token, now))
    conn.commit()
    conn.close()
    
    return jsonify({
        'token': token,
        'user_id': user['id'],
        'nombre': user['nombre'],
        'es_admin': bool(user['es_admin']),
        'trial_end': user['trial_end'],
        'subscription_end': user['subscription_end']
    })

@app.route('/api/verificar_suscripcion', methods=['GET'])
@verificar_token
def verificar_suscripcion():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT trial_end, subscription_end FROM usuarios WHERE id = ?", (request.user_id,))
    user = cursor.fetchone()
    conn.close()
    
    today = datetime.date.today().isoformat()
    tiene_acceso = False
    
    if user['subscription_end'] and user['subscription_end'] >= today:
        tiene_acceso = True
    elif user['trial_end'] and user['trial_end'] >= today:
        tiene_acceso = True
    
    return jsonify({
        'tiene_acceso': tiene_acceso,
        'trial_end': user['trial_end'],
        'subscription_end': user['subscription_end']
    })

@app.route('/api/buscar', methods=['GET'])
@verificar_token
def buscar():
    """Busca en TODAS las filas del Excel"""
    termino = request.args.get('q', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    if termino:
        cursor.execute("SELECT texto, tipo, precio, unidad, fila_original FROM items WHERE LOWER(texto) LIKE LOWER(?) LIMIT 500", (f"%{termino}%",))
    else:
        cursor.execute("SELECT texto, tipo, precio, unidad, fila_original FROM items LIMIT 200")
    
    resultados = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in resultados])

@app.route('/api/sincronizar', methods=['POST'])
@verificar_token
def sincronizar():
    """Sube el Excel y guarda CADA FILA con todo su contenido"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT es_admin FROM usuarios WHERE id = ?", (request.user_id,))
    user = cursor.fetchone()
    
    if not user or not user['es_admin']:
        conn.close()
        return jsonify({'error': 'No autorizado'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No se envió archivo'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Archivo vacío'}), 400
    
    temp_path = 'temp_excel.xlsx'
    file.save(temp_path)
    
    try:
        df = pd.read_excel(temp_path, sheet_name=0)
        
        # Limpiar datos existentes
        cursor.execute("DELETE FROM items")
        
        contador = 0
        
        # Recorrer CADA FILA del Excel
        for idx, row in df.iterrows():
            fila_completa = []
            precio = 0
            unidad = ""
            tipo = "producto"
            
            # Recorrer CADA COLUMNA de la fila
            for col in df.columns:
                valor = str(row[col]) if pd.notna(row[col]) else ""
                if valor and valor != 'nan' and len(valor) > 1:
                    fila_completa.append(f"{col}: {valor}")
                    
                    # Detectar si es un precio
                    if 'precio' in col.lower() or 'total' in col.lower():
                        try:
                            valor_limpio = valor.replace(',', '').replace('Bs', '').strip()
                            precio = float(valor_limpio) if valor_limpio else 0
                        except:
                            pass
                    
                    # Detectar unidad
                    if col in ['U', 'u', 'Unidad', 'UNIDAD']:
                        unidad = valor[:20]
                    
                    # Detectar si es empresa/proveedor
                    if any(p in valor.upper() for p in ['SRL', 'LTDA', 'S.A.', 'CONSTRUCTORA', 'EMPRESA', 'ACERMAX', 'SOBOCE']):
                        tipo = "empresa"
            
            # Si la fila tiene contenido, guardarla
            if fila_completa:
                texto_principal = str(row.get('Descripción', row.get('descripcion', row.get('Item', ''))))
                if not texto_principal or texto_principal == 'nan':
                    texto_principal = fila_completa[0][:200] if fila_completa else "Sin título"
                
                cursor.execute('''INSERT INTO items 
                    (texto, tipo, precio, unidad, fila_original) 
                    VALUES (?, ?, ?, ?, ?)''',
                    (texto_principal[:200], tipo, precio, unidad, "\n".join(fila_completa)[:2000]))
                contador += 1
        
        conn.commit()
        os.remove(temp_path)
        conn.close()
        
        print(f"✅ Sincronizado: {contador} filas del Excel")
        return jsonify({'message': f'✅ {contador} registros sincronizados'})
        
    except Exception as e:
        conn.close()
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': str(e)}), 500

@app.route('/api/version', methods=['GET'])
def version():
    return jsonify({'status': 'ok', 'message': 'PriceWise Server'})

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("💰 PRICEWISE - SERVIDOR")
    print("📍 http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)