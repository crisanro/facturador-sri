import mysql.connector
from mysql.connector import Error
import os

# --- CONFIGURACIÓN SEGURA ---
# Lee las variables de EasyPanel o usa valores por defecto en local
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'db-facturacion'),
    'port': int(os.getenv('DB_PORT', 3306))
}

def get_db_connection():
    """Crea la conexión a la base de datos"""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"Error conectando a MySQL: {e}")
        return None

def inicializar_tablas():
    """Crea las tablas necesarias si no existen"""
    conn = get_db_connection()
    if conn is None: return
    cursor = conn.cursor()
    
    # 1. Tabla EMPRESAS (Clientes)
    # Nota: firma_path y firma_clave aceptan NULL para permitir registro sin archivo inicial
    sql_empresas = """
    CREATE TABLE IF NOT EXISTS empresas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ruc VARCHAR(13) NOT NULL UNIQUE,
        razon_social VARCHAR(300) NOT NULL,
        email VARCHAR(255),
        telefono VARCHAR(50),
        password_hash VARCHAR(255),
        firma_path VARCHAR(255) NULL,
        firma_clave VARCHAR(255) NULL,
        creditos INT DEFAULT 10,
        activo BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    # 2. Tabla PUNTOS DE EMISION (Control de secuenciales)
    sql_puntos = """
    CREATE TABLE IF NOT EXISTS puntos_emision (
        id INT AUTO_INCREMENT PRIMARY KEY,
        empresa_id INT,
        serie VARCHAR(6) NOT NULL, 
        ultimo_secuencial INT DEFAULT 0,
        FOREIGN KEY (empresa_id) REFERENCES empresas(id),
        UNIQUE(empresa_id, serie) 
    );
    """

    # 3. Tabla COMPROBANTES (Facturas)
    sql_comprobantes = """
    CREATE TABLE IF NOT EXISTS comprobantes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        empresa_id INT,
        clave_acceso VARCHAR(49) NOT NULL UNIQUE,
        tipo_comprobante VARCHAR(2) NOT NULL,
        xml_generado LONGTEXT,
        estado VARCHAR(20) DEFAULT 'CREADO',
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (empresa_id) REFERENCES empresas(id)
    );
    """
    
    try:
        cursor.execute(sql_empresas)
        cursor.execute(sql_puntos)
        cursor.execute(sql_comprobantes)
        conn.commit()
        print("✅ Tablas de base de datos verificadas/creadas.")
    except Error as e:
        print(f"❌ Error inicializando tablas: {e}")
    finally:
        cursor.close()
        conn.close()

# --- FUNCIONES DE GESTIÓN DE EMPRESAS ---

def crear_empresa(ruc, razon_social, pass_hash, email, telefono):
    """Registra una nueva empresa (sin firma al inicio)"""
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        # Insertamos NULL en los campos de firma
        sql = """INSERT INTO empresas (ruc, razon_social, password_hash, email, telefono, firma_path, firma_clave) 
                 VALUES (%s, %s, %s, %s, %s, NULL, NULL)"""
        cursor.execute(sql, (ruc, razon_social, pass_hash, email, telefono))
        conn.commit()
        return True
    except Error as e:
        print(f"Error creando empresa: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def actualizar_firma_cliente(ruc, path_firma, clave_firma):
    """Guarda la ruta y clave del .p12 cuando el cliente lo sube"""
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET firma_path = %s, firma_clave = %s WHERE ruc = %s"
        cursor.execute(sql, (path_firma, clave_firma, ruc))
        conn.commit()
        return True
    except Error as e:
        print(f"Error actualizando firma: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def buscar_empresa_por_ruc(ruc):
    """Busca datos de empresa para login y facturación"""
    conn = get_db_connection()
    if not conn: return None
    # dictionary=True es vital para acceder como empresa['id']
    cursor = conn.cursor(dictionary=True) 
    try:
        cursor.execute("SELECT * FROM empresas WHERE ruc = %s AND activo = 1", (ruc,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

# --- FUNCIONES DE FACTURACIÓN ---

def obtener_siguiente_secuencial(empresa_id, serie):
    """Calcula el número de factura automático (1, 2, 3...)"""
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor()
    try:
        # 1. Intentar incrementar
        sql_update = "UPDATE puntos_emision SET ultimo_secuencial = ultimo_secuencial + 1 WHERE empresa_id = %s AND serie = %s"
        cursor.execute(sql_update, (empresa_id, serie))
        
        # 2. Si no existía, crear el registro inicial
        if cursor.rowcount == 0:
            sql_insert = "INSERT INTO puntos_emision (empresa_id, serie, ultimo_secuencial) VALUES (%s, %s, 1)"
            cursor.execute(sql_insert, (empresa_id, serie))
            conn.commit()
            return 1
            
        conn.commit()
        
        # 3. Obtener el valor actualizado
        cursor.execute("SELECT ultimo_secuencial FROM puntos_emision WHERE empresa_id = %s AND serie = %s", (empresa_id, serie))
        res = cursor.fetchone()
        return res[0] if res else None
    except Error as e:
        print(f"Error secuencial: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def guardar_factura_bd(empresa_id, clave, tipo, xml):
    """Guarda el XML final en la base de datos"""
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "INSERT INTO comprobantes (empresa_id, clave_acceso, tipo_comprobante, xml_generado) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (empresa_id, clave, tipo, xml))
        conn.commit()
        return True
    except Error as e:
        print(f"Error guardando factura: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

# --- FUNCIONES DE CRÉDITOS (ECONOMÍA) ---

def descontar_credito(empresa_id):
    """Resta 1 crédito al emitir factura"""
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET creditos = creditos - 1 WHERE id = %s AND creditos > 0"
        cursor.execute(sql, (empresa_id,))
        conn.commit()
        return cursor.rowcount > 0 
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()

def recargar_creditos(ruc, cantidad):
    """Suma créditos (Usado por el Admin)"""
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET creditos = creditos + %s WHERE ruc = %s"
        cursor.execute(sql, (cantidad, ruc))
        conn.commit()
        # Verificar si se actualizó alguien (si el RUC existe)
        return cursor.rowcount > 0
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()
