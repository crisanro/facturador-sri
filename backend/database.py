import mysql.connector
from mysql.connector import Error
import os

# --- CONFIGURACIÓN DE TU BASE DE DATOS ---
# Si estás probando en tu PC y no tienes MySQL instalado, 
# esto dará error hasta que lo subas a EasyPanel o instales MySQL local.

DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'), # ¡Aquí déjalo vacío! La inyectaremos desde fuera
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT'))
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
    
    # 1. Tabla EMPRESAS (Clientes)
sql_empresas = """
    CREATE TABLE IF NOT EXISTS empresas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ruc VARCHAR(13) NOT NULL UNIQUE,
        razon_social VARCHAR(300) NOT NULL,
        email VARCHAR(255),        -- NUEVO
        telefono VARCHAR(50),      -- NUEVO
        password_hash VARCHAR(255),
        firma_path VARCHAR(255) NULL, -- AHORA PUEDE SER NULL (VACÍO)
        firma_clave VARCHAR(255) NULL, -- AHORA PUEDE SER NULL
        creditos INT DEFAULT 10,
        activo BOOLEAN DEFAULT 1
    );
    """
    
    # 2. Tabla SECUENCIALES (Control de números)
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
        print("✅ Base de datos inicializada correctamente.")
    except Error as e:
        print(f"❌ Error DB Init: {e}")
    finally:
        cursor.close()
        conn.close()

# --- FUNCIONES DE LÓGICA ---

def crear_empresa(ruc, razon_social, pass_hash, email, telefono):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        # Al registrarse, firma_path y firma_clave van vacíos (None)
        sql = """INSERT INTO empresas (ruc, razon_social, password_hash, email, telefono, firma_path, firma_clave) 
                 VALUES (%s, %s, %s, %s, %s, NULL, NULL)"""
        cursor.execute(sql, (ruc, razon_social, pass_hash, email, telefono))
        conn.commit()
        return True
    except Error as e:
        print(f"Error crear empresa: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

# NUEVA FUNCIÓN: ACTUALIZAR FIRMA
def actualizar_firma_cliente(ruc, path_firma, clave_firma):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET firma_path = %s, firma_clave = %s WHERE ruc = %s"
        cursor.execute(sql, (path_firma, clave_firma, ruc))
        conn.commit()
        return True
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()

def buscar_empresa_por_ruc(ruc):
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM empresas WHERE ruc = %s", (ruc,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def obtener_siguiente_secuencial(empresa_id, serie):
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor()
    try:
        # Intenta actualizar sumando 1
        sql_update = "UPDATE puntos_emision SET ultimo_secuencial = ultimo_secuencial + 1 WHERE empresa_id = %s AND serie = %s"
        cursor.execute(sql_update, (empresa_id, serie))
        
        # Si no existía, lo crea empezando en 1
        if cursor.rowcount == 0:
            sql_insert = "INSERT INTO puntos_emision (empresa_id, serie, ultimo_secuencial) VALUES (%s, %s, 1)"
            cursor.execute(sql_insert, (empresa_id, serie))
            conn.commit()
            return 1
            
        conn.commit()
        # Devuelve el número actual
        cursor.execute("SELECT ultimo_secuencial FROM puntos_emision WHERE empresa_id = %s AND serie = %s", (empresa_id, serie))
        res = cursor.fetchone()
        return res[0] if res else None
    except Error as e:
        print(f"Error Secuencial: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def guardar_factura_bd(empresa_id, clave, tipo, xml):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "INSERT INTO comprobantes (empresa_id, clave_acceso, tipo_comprobante, xml_generado) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (empresa_id, clave, tipo, xml))
        conn.commit()
        return True
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()


def descontar_credito(empresa_id):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        # Restamos 1 solo si tiene saldo positivo
        sql = "UPDATE empresas SET creditos = creditos - 1 WHERE id = %s AND creditos > 0"
        cursor.execute(sql, (empresa_id,))
        conn.commit()
        
        # rowcount nos dice cuántas filas cambió. Si es 0, es que no tenía saldo.
        return cursor.rowcount > 0 
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()

# --- NUEVA FUNCIÓN (ADMIN): RECARGAR SALDO ---
def recargar_creditos(ruc, cantidad):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        sql = "UPDATE empresas SET creditos = creditos + %s WHERE ruc = %s"
        cursor.execute(sql, (cantidad, ruc))
        conn.commit()
        return True
    finally:
        cursor.close()

        conn.close()
