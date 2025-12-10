import xml.etree.ElementTree as ET
from xml.dom import minidom # Para que el XML se vea bonito (indentado)

def crear_xml_factura(factura, clave_acceso):
    """
    Construye el XML de la factura versión 1.1.0
    Referencia: Anexo 3 de la Ficha Técnica
    """
    # 1. Raíz del XML
    factura_xml = ET.Element('factura', id="comprobante", version="1.1.0")

    # 2. Bloque <infoTributaria> [cite: 821]
    info_tributaria = ET.SubElement(factura_xml, 'infoTributaria')
    ET.SubElement(info_tributaria, 'ambiente').text = str(factura.ambiente)
    ET.SubElement(info_tributaria, 'tipoEmision').text = "1" # Normal
    ET.SubElement(info_tributaria, 'razonSocial').text = factura.razon_social_emisor
    ET.SubElement(info_tributaria, 'nombreComercial').text = factura.nombre_comercial or factura.razon_social_emisor
    ET.SubElement(info_tributaria, 'ruc').text = factura.ruc
    ET.SubElement(info_tributaria, 'claveAcceso').text = clave_acceso
    ET.SubElement(info_tributaria, 'codDoc').text = "01" # 01 es Factura
    ET.SubElement(info_tributaria, 'estab').text = factura.serie[0:3]
    ET.SubElement(info_tributaria, 'ptoEmi').text = factura.serie[3:6]
    ET.SubElement(info_tributaria, 'secuencial').text = str(factura.secuencial).zfill(9)
    ET.SubElement(info_tributaria, 'dirMatriz').text = factura.direccion_matriz

    # 3. Bloque <infoFactura> [cite: 821]
    info_factura = ET.SubElement(factura_xml, 'infoFactura')
    ET.SubElement(info_factura, 'fechaEmision').text = factura.fecha_emision
    ET.SubElement(info_factura, 'dirEstablecimiento').text = factura.direccion_establecimiento
    ET.SubElement(info_factura, 'obligadoContabilidad').text = factura.obligado_contabilidad
    ET.SubElement(info_factura, 'tipoIdentificacionComprador').text = factura.tipo_identificacion_comprador
    ET.SubElement(info_factura, 'razonSocialComprador').text = factura.razon_social_comprador
    ET.SubElement(info_factura, 'identificacionComprador').text = factura.identificacion_comprador
    ET.SubElement(info_factura, 'totalSinImpuestos').text = "{:.2f}".format(factura.total_sin_impuestos)
    ET.SubElement(info_factura, 'totalDescuento').text = "{:.2f}".format(factura.total_descuento)
    
    # Bloque de Impuestos Totales [cite: 823]
    total_con_impuestos = ET.SubElement(info_factura, 'totalConImpuestos')
    for imp in factura.total_impuestos:
        total_imp = ET.SubElement(total_con_impuestos, 'totalImpuesto')
        ET.SubElement(total_imp, 'codigo').text = imp.codigo
        ET.SubElement(total_imp, 'codigoPorcentaje').text = imp.codigo_porcentaje
        ET.SubElement(total_imp, 'baseImponible').text = "{:.2f}".format(imp.base_imponible)
        ET.SubElement(total_imp, 'valor').text = "{:.2f}".format(imp.valor)

    ET.SubElement(info_factura, 'propina').text = "{:.2f}".format(factura.propina)
    ET.SubElement(info_factura, 'importeTotal').text = "{:.2f}".format(factura.importe_total)
    ET.SubElement(info_factura, 'moneda').text = "DOLAR"
    
    # Pagos [cite: 823]
    pagos = ET.SubElement(info_factura, 'pagos')
    pago = ET.SubElement(pagos, 'pago')
    ET.SubElement(pago, 'formaPago').text = factura.forma_pago
    ET.SubElement(pago, 'total').text = "{:.2f}".format(factura.importe_total)

    # 4. Bloque <detalles> (Productos) [cite: 823]
    detalles = ET.SubElement(factura_xml, 'detalles')
    for item in factura.detalles:
        detalle = ET.SubElement(detalles, 'detalle')
        ET.SubElement(detalle, 'codigoPrincipal').text = item.codigo_principal
        ET.SubElement(detalle, 'descripcion').text = item.descripcion
        ET.SubElement(detalle, 'cantidad').text = "{:.6f}".format(item.cantidad) # Versión 1.1.0 permite 6 decimales
        ET.SubElement(detalle, 'precioUnitario').text = "{:.6f}".format(item.precio_unitario)
        ET.SubElement(detalle, 'descuento').text = "{:.2f}".format(item.descuento)
        ET.SubElement(detalle, 'precioTotalSinImpuesto').text = "{:.2f}".format(item.precio_total_sin_impuesto)
        
        # Impuestos por producto [cite: 824]
        impuestos_det = ET.SubElement(detalle, 'impuestos')
        impuesto_det = ET.SubElement(impuestos_det, 'impuesto')
        ET.SubElement(impuesto_det, 'codigo').text = item.codigo_impuesto
        ET.SubElement(impuesto_det, 'codigoPorcentaje').text = item.codigo_porcentaje
        ET.SubElement(impuesto_det, 'tarifa').text = "{:.2f}".format(item.tarifa)
        ET.SubElement(impuesto_det, 'baseImponible').text = "{:.2f}".format(item.base_imponible)
        ET.SubElement(impuesto_det, 'valor').text = "{:.2f}".format(item.valor_impuesto)

    # Convertir a string
    xml_str = ET.tostring(factura_xml, encoding='utf-8', method='xml')
    
    # "Pretty print" (opcional, para que se lea bien si lo imprimes)
    parsed_xml = minidom.parseString(xml_str)
    return parsed_xml.toprettyxml(indent="  ")