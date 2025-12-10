import random
from itertools import cycle

def calcular_modulo11(clave_sin_digito):
    """
    Calcula el dígito verificador usando el algoritmo Módulo 11 
    con factor de chequeo ponderado (2 a 7).
    Referencia: Ficha Técnica SRI - Numeral 5.2 
    """
    # Invertimos la cadena para facilitar la multiplicación por la secuencia 2,3,4,5,6,7
    clave_invertida = clave_sin_digito[::-1]
    
    # La secuencia de multiplicadores es 2, 3, 4, 5, 6, 7 repetidamente
    multiplicadores = cycle([2, 3, 4, 5, 6, 7])
    
    suma = 0
    for digito, peso in zip(clave_invertida, multiplicadores):
        suma += int(digito) * peso
    
    residuo = suma % 11
    resultado = 11 - residuo
    
    # Reglas especiales del SRI[cite: 96]:
    if resultado == 11:
        digito_verificador = 0
    elif resultado == 10:
        digito_verificador = 1
    else:
        digito_verificador = resultado
        
    return str(digito_verificador)

def generar_clave_acceso(fecha_emision, tipo_comprobante, ruc, ambiente, 
                         serie, secuencial, codigo_numerico=None):
    """
    Genera la clave de acceso de 49 dígitos.
    Estructura basada en Tabla 1 de la Ficha Técnica[cite: 93].
    """
    
    # 1. Validación y Formateo de datos
    # Fecha debe ser ddmmaaaa (8 dígitos) [cite: 93]
    fecha = fecha_emision.replace('/', '').replace('-', '') 
    
    # RUC (13 dígitos) [cite: 93]
    ruc = str(ruc).zfill(13)
    
    # Ambiente: 1=Pruebas, 2=Producción [cite: 124]
    ambiente = str(ambiente)
    
    # Serie: Establecimiento (3) + Punto Emisión (3) = 6 dígitos [cite: 93]
    serie = str(serie).replace('-', '').zfill(6)
    
    # Secuencial: 9 dígitos [cite: 93]
    secuencial = str(secuencial).zfill(9)
    
    # Código Numérico: 8 dígitos. Si no se envía, se genera aleatorio [cite: 93]
    if codigo_numerico is None:
        # Generamos 8 dígitos aleatorios
        codigo_numerico = str(random.randint(1, 99999999)).zfill(8)
    else:
        codigo_numerico = str(codigo_numerico).zfill(8)
        
    # Tipo Emisión: Siempre es '1' (Emisión Normal) en esquema Offline [cite: 114]
    tipo_emision = '1' 
    
    # 2. Concatenación de los primeros 48 dígitos
    clave_temporal = (
        f"{fecha}"
        f"{tipo_comprobante}"
        f"{ruc}"
        f"{ambiente}"
        f"{serie}"
        f"{secuencial}"
        f"{codigo_numerico}"
        f"{tipo_emision}"
    )
    
    # 3. Calcular Dígito Verificador (Módulo 11) 
    digito_verificador = calcular_modulo11(clave_temporal)
    
    # 4. Retornar Clave de Acceso Completa (49 dígitos)
    clave_acceso = clave_temporal + digito_verificador
    
    return clave_acceso

# --- ZONA DE PRUEBAS ---
if __name__ == "__main__":
    # Ejemplo de uso:
    # Tipo 01 = Factura [cite: 118]
    # Ambiente 1 = Pruebas [cite: 124]
    
    mi_clave = generar_clave_acceso(
        fecha_emision="10122025", 
        tipo_comprobante="01", 
        ruc="1760013210001", 
        ambiente="1", 
        serie="001001", 
        secuencial="123",  # El código lo rellenará a 000000123
        codigo_numerico="12345678" 
    )
    
    print(f"Clave generada: {mi_clave}")
    print(f"Longitud: {len(mi_clave)}") # Debe ser 49