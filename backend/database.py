import mysql.connector
from mysql.connector import Error
import os

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
    
    # MODIFICAMOS LA TABLA PARA EL NUEVO FLUJO
    # 1. RUC ahora puede ser NULL al inicio.
    # 2. Email es UNIQUE (nadie puede registrarse con el mismo correo).
    # 3. Agregamos 'codigo_verificacion' y 'email_verificado'.
    
    sql_empresas = """
    CREATE TABLE IF NOT EXISTS empresas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,  -- Login principal
        password_hash VARCHAR(255) NOT NULL, -- Contraseña encriptada
        nombre_usuario VARCHAR(150),         -- Nombre de la persona (ej: Juan)
        
        -- DATOS DE EMPRESA (Se llenan después)
        ruc VARCHAR(13) NULL UNIQUE,         
        razon_social VARCHAR(300) NULL,
        telefono VARCHAR(50),
        
        -- DATOS DE FIRMA (Se llenan después)
        firma_path VARCHAR(255) NULL,
        firma_clave VARCHAR(255) NULL,
        
        -- DATOS DE CONTROL
        creditos INT DEFAULT 10,
        codigo_verificacion VARCHAR(6),      -- El código de seguridad que pediste
        email_verificado BOOLEAN DEFAULT 0,  -- 0 = No, 1 = Si
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    # ... (Tablas puntos_emision y comprobantes quedan igual que antes) ...
    # Asegúrate de copiar las definiciones de sql_puntos y sql_comprobantes del código anterior aquí.
    # ...
    
    sql_puntos = """CREATE TABLE IF NOT EXISTS puntos_emision (id INT AUTO_INCREMENT PRIMARY KEY, empresa_id INT, serie VARCHAR(6) NOT NULL, ultimo_secuencial INT DEFAULT 0, FOREIGN KEY (empresa_id) REFERENCES empresas(id), UNIQUE(empresa_id, serie));"""
    sql_comprobantes = """CREATE TABLE IF NOT EXISTS comprobantes (id INT AUTO_INCREMENT PRIMARY KEY, empresa_id INT, clave_acceso VARCHAR(49) NOT NULL UNIQUE, tipo_comprobante VARCHAR(2) NOT NULL, xml_generado LONGTEXT, estado VARCHAR(20) DEFAULT 'CREADO', fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (empresa_id) REFERENCES empresas(id));"""

    try:
        cursor.execute(sql_empresas)
        cursor.execute(sql_puntos)
        cursor.execute(sql_comprobantes)
        conn.commit()
        print("✅ Base de datos actualizada para registro por Email.")
    except Error as e:
        print(f"❌ Error DB: {e}")
    finally:
        cursor.close()
        conn.close()

# --- NUEVAS FUNCIONES ---

def registrar_usuario_inicial(nombre, email, pass_hash, codigo_verificacion):
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
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        # Busca si coincide el código
        sql = "UPDATE empresas SET email_verificado = 1 WHERE email = %s AND codigo_verificacion = %s"
        cursor.execute(sql, (email, codigo))
        conn.commit()
        return cursor.rowcount > 0 # Devuelve True si se actualizó (código correcto)
    finally:
        cursor.close()
        conn.close()

def buscar_usuario_por_email(email):
    """Usada para el Login"""
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
    """Usada para validar que no se repita el RUC al configurar"""
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
    """Este es el paso 2: Cuando ya sube la firma y el RUC"""
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

# ... (Mantén las funciones de obtener_siguiente_secuencial, guardar_factura_bd, etc.) ...
def obtener_siguiente_secuencial(empresa_id, serie):
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

def guardar_factura_bd(empresa_id, clave, tipo, xml):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "INSERT INTO comprobantes (empresa_id, clave_acceso, tipo_comprobante, xml_generado) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (empresa_id, clave, tipo, xml))
        conn.commit()
        return True
    except Error: return False
    finally: cursor.close(); conn.close()

def descontar_credito(empresa_id):
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

def recargar_creditos(ruc, cantidad):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET creditos = creditos + %s WHERE ruc = %s"
        cursor.execute(sql, (cantidad, ruc))
        conn.commit()
        return True
    except Error: return False
    finally: cursor.close(); conn.close()

