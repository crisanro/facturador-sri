import mysql.connector
from mysql.connector import Error
import os
import secrets
import uuid

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'db-facturacion'),
    'port': int(os.getenv('DB_PORT', 3306))
}

def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"Error MySQL: {e}")
        return None

def inicializar_tablas():
    conn = get_db_connection()
    if conn is None: return
    cursor = conn.cursor()
    
    # Tabla Empresas (sin cambios)
    sql_empresas = """
    CREATE TABLE IF NOT EXISTS empresas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        nombre_usuario VARCHAR(150),
        ruc VARCHAR(13) NULL UNIQUE,
        razon_social VARCHAR(300) NULL,
        telefono VARCHAR(50),
        firma_path VARCHAR(255) NULL,
        firma_clave VARCHAR(255) NULL,
        api_key VARCHAR(64) NULL UNIQUE,
        creditos INT DEFAULT 10,
        codigo_verificacion VARCHAR(6),
        email_verificado BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    # Tablas existentes
    sql_puntos = """
    CREATE TABLE IF NOT EXISTS puntos_emision (id INT AUTO_INCREMENT PRIMARY KEY, empresa_id INT, serie VARCHAR(6) NOT NULL, ultimo_secuencial INT DEFAULT 0, FOREIGN KEY (empresa_id) REFERENCES empresas(id), UNIQUE(empresa_id, serie));
    """
    sql_comprobantes = """
    CREATE TABLE IF NOT EXISTS comprobantes (id INT AUTO_INCREMENT PRIMARY KEY, empresa_id INT, clave_acceso VARCHAR(49) NOT NULL UNIQUE, tipo_comprobante VARCHAR(2) NOT NULL, xml_generado LONGTEXT, estado VARCHAR(20) DEFAULT 'CREADO', fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (empresa_id) REFERENCES empresas(id));
    """
    
    # TABLA DE TRANSACCIONES (PARA STRPPE)
    sql_transacciones = """
    CREATE TABLE IF NOT EXISTS transacciones (
        id INT AUTO_INCREMENT PRIMARY KEY,
        empresa_id INT NOT NULL,
        monto_usd DECIMAL(10, 2) NOT NULL,
        creditos_recargados INT NOT NULL,
        estado VARCHAR(50) DEFAULT 'COMPLETADO',
        referencia_pago VARCHAR(255) NULL, -- ID de sesión de Stripe
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (empresa_id) REFERENCES empresas(id)
    );
    """

    try:
        cursor.execute(sql_empresas)
        cursor.execute(sql_puntos)
        cursor.execute(sql_comprobantes)
        # !!! NUEVO: EJECUTAR LA CREACIÓN DE LA TABLA TRANSACCIONES !!!
        cursor.execute(sql_transacciones) 
        
        conn.commit()
        print("✅ Base de datos actualizada para registro por Email.")
    except Error as e:
        print(f"❌ Error DB: {e}")
    finally:
        cursor.close()
        conn.close()

# --- FUNCIONES DE AUTENTICACIÓN Y CONFIGURACIÓN (MANTENEMOS IGUAL) ---

def registrar_usuario_inicial(nombre, email, pass_hash, codigo_verificacion):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = """INSERT INTO empresas (nombre_usuario, email, password_hash, codigo_verificacion, email_verificado) 
                 VALUES (%s, %s, %s, %s, 0)"""
        cursor.execute(sql, (nombre, email, pass_hash, codigo_verificacion))
        conn.commit()
        return True
    except Error as e:
        print(f"Error registro: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def verificar_codigo_email(email, codigo):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET email_verificado = 1 WHERE email = %s AND codigo_verificacion = %s"
        cursor.execute(sql, (email, codigo))
        conn.commit()
        return cursor.rowcount > 0 
    finally:
        cursor.close()
        conn.close()

def buscar_usuario_por_email(email):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM empresas WHERE email = %s", (email,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def buscar_empresa_por_ruc(ruc):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM empresas WHERE ruc = %s", (ruc,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def completar_datos_empresa(email_usuario, ruc, razon_social, path_firma, clave_firma):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = """UPDATE empresas 
                 SET ruc = %s, razon_social = %s, firma_path = %s, firma_clave = %s 
                 WHERE email = %s"""
        cursor.execute(sql, (ruc, razon_social, path_firma, clave_firma, email_usuario))
        conn.commit()
        return True
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()

# --- FUNCIONES DE FACTURACIÓN (MANTENEMOS IGUAL) ---

def obtener_siguiente_secuencial(empresa_id, serie):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor()
    try:
        sql_update = "UPDATE puntos_emision SET ultimo_secuencial = ultimo_secuencial + 1 WHERE empresa_id = %s AND serie = %s"
        cursor.execute(sql_update, (empresa_id, serie))
        if cursor.rowcount == 0:
            sql_insert = "INSERT INTO puntos_emision (empresa_id, serie, ultimo_secuencial) VALUES (%s, %s, 1)"
            cursor.execute(sql_insert, (empresa_id, serie))
            conn.commit()
            return 1
        conn.commit()
        cursor.execute("SELECT ultimo_secuencial FROM puntos_emision WHERE empresa_id = %s AND serie = %s", (empresa_id, serie))
        res = cursor.fetchone()
        return res[0] if res else None
    except Error: return None
    finally: cursor.close(); conn.close()

# MODIFICACIÓN: Aceptar el estado del SRI para guardarlo
def guardar_factura_bd(empresa_id, clave, tipo, xml, estado_inicial='CREADO'): # Agregamos 'estado_inicial'
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        # Insertamos el estado inicial recibido del WS de Recepción
        sql = "INSERT INTO comprobantes (empresa_id, clave_acceso, tipo_comprobante, xml_generado, estado) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(sql, (empresa_id, clave, tipo, xml, estado_inicial))
        conn.commit()
        return True
    except Error: return False
    finally: cursor.close(); conn.close()

def descontar_credito(empresa_id):
# ... (Función existente) ...
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET creditos = creditos - 1 WHERE id = %s AND creditos > 0"
        cursor.execute(sql, (empresa_id,))
        conn.commit()
        return cursor.rowcount > 0 
    except Error: return False
    finally: cursor.close(); conn.close()


# --- FUNCIONES DE MONETIZACIÓN (PASO B Y C) ---

# MODIFICACIÓN CRÍTICA: Reemplaza la antigua recargar_creditos
def registrar_recarga_y_aumentar_creditos(ruc, cantidad, monto_usd, referencia_pago): 
    """Registra la transacción en la tabla 'transacciones' y aumenta los créditos."""
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        # 1. Obtener ID de la empresa
        cursor.execute("SELECT id FROM empresas WHERE ruc = %s", (ruc,))
        res = cursor.fetchone()
        if not res: return False
        empresa_id = res[0]
        
        # 2. Aumentar créditos
        sql_update = "UPDATE empresas SET creditos = creditos + %s WHERE id = %s"
        cursor.execute(sql_update, (cantidad, empresa_id))
        
        # 3. Registrar la transacción
        sql_insert = """INSERT INTO transacciones (empresa_id, monto_usd, creditos_recargados, referencia_pago) 
                        VALUES (%s, %s, %s, %s)"""
        cursor.execute(sql_insert, (empresa_id, monto_usd, cantidad, referencia_pago))

        conn.commit()
        return True
    except Error as e: 
        print(f"Error registrando recarga: {e}")
        return False
    finally: cursor.close(); conn.close()


# NUEVA FUNCIÓN: Historial de Transacciones (para el dashboard del cliente)
def obtener_historial_transacciones(empresa_id):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT fecha_creacion, monto_usd, creditos_recargados, estado, referencia_pago FROM transacciones WHERE empresa_id = %s ORDER BY fecha_creacion DESC", (empresa_id,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

# NUEVA FUNCIÓN: Historial de Comprobantes (para el dashboard del cliente)
def obtener_historial_comprobantes(empresa_id):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(dictionary=True)
    try:
        sql = """SELECT clave_acceso, tipo_comprobante, estado, fecha_creacion 
                 FROM comprobantes 
                 WHERE empresa_id = %s 
                 ORDER BY fecha_creacion DESC"""
        cursor.execute(sql, (empresa_id,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
        
# NUEVA FUNCIÓN: Monto Total Ganado (para el dashboard de administración)
def obtener_monto_total_ganado():
    conn = get_db_connection()
    if not conn: return 0.0
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SUM(monto_usd) FROM transacciones WHERE estado = 'COMPLETADO'")
        res = cursor.fetchone()
        # Aseguramos que el resultado sea float o 0.0
        return float(res[0]) if res and res[0] else 0.0
    except Error: return 0.0
    finally:
        cursor.close()
        conn.close()

def generar_api_key(empresa_id):
    """Genera un token largo y aleatorio para el acceso a la API."""
    # 32 bytes de secreto = 64 caracteres en hexadecimal
    new_key = secrets.token_hex(32)
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET api_key = %s WHERE id = %s"
        cursor.execute(sql, (new_key, empresa_id))
        conn.commit()
        return new_key
    except Error: return None
    finally: cursor.close(); conn.close()

def buscar_usuario_por_api_key(api_key):
    """Busca el usuario completo por la API Key (para el header de facturación)."""
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM empresas WHERE api_key = %s", (api_key,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def generar_uuid_api_key():
    """Genera una API Key fuerte usando UUID4 y la convierte a string"""
    # Usamos 32 caracteres de UUID4 sin guiones.
    return str(uuid.uuid4()).replace('-', '')

def generar_api_key(user_id: int):
    """Genera una nueva API Key y la guarda en la base de datos para el usuario."""
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor()
    
    nueva_key = generar_uuid_api_key()
    
    try:
        sql = "UPDATE empresas SET api_key = %s WHERE id = %s"
        cursor.execute(sql, (nueva_key, user_id))
        conn.commit()
        
        if cursor.rowcount > 0:
            return nueva_key # Retorna la clave generada si fue exitoso
        return None
        
    except Error as e:
        print(f"Error al guardar API Key: {e}")
        return None
        
    finally: 
        cursor.close()
        conn.close()

