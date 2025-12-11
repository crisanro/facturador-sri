import stripe
import os
import database # Importar la BD para la recarga

# Configurar la clave secreta de Stripe
# ¡USA UNA VARIABLE DE ENTORNO O SECRET MANAGER!
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

# Precio de ejemplo (Se recomienda usar Stripe Products/Prices)
PRECIOS = {
    50: 1000, # 50 créditos por $10.00 (en centavos)
    100: 1800 # 100 créditos por $18.00 (en centavos)
}
CREDITOS = {
    1000: 50,  # $10.00 (1000 centavos) = 50 facturas
    1800: 100, # $18.00 (1800 centavos) = 100 facturas
}

def crear_sesion_checkout(user_id, ruc_cliente, cantidad_creditos):
    """
    Crea una sesión de checkout de Stripe.
    """
    precio_centavos = PRECIOS.get(cantidad_creditos)
    if not precio_centavos:
        raise ValueError("Cantidad de créditos no válida.")
        
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'{cantidad_creditos} Créditos de Facturación SRI',
                    },
                    'unit_amount': precio_centavos,
                },
                'quantity': 1,
            }],
            mode='payment',
            # Usamos el RUC como referencia para saber a quién recargar
            success_url=f'http://tudominio.com/compra-exitosa?ruc={ruc_cliente}',
            cancel_url='http://tudominio.com/compra-cancelada',
            # Metadatos para el webhook
            metadata={
                'ruc': ruc_cliente,
                'user_id': user_id,
                'creditos_a_recargar': cantidad_creditos
            }
        )
        return session.url
    except Exception as e:
        print(f"Error creando sesión Stripe: {e}")
        return None

def procesar_webhook(payload, sig_header, webhook_secret):
    """
    Verifica el evento y recarga los créditos. ESTA ES LA LÓGICA INTERNA.
    """
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return "Invalid signature", 400

    # Manejar el evento (Solo recargamos si el pago fue completado)
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # 1. Extraer los datos guardados en metadatos
        ruc = session['metadata']['ruc']
        creditos = int(session['metadata']['creditos_a_recargar'])
        
        # 2. VALIDACIÓN CRÍTICA: Asegurarse de que el pago esté confirmado
        if session.payment_status == "paid":
            # 3. Aumentar los créditos en la BD (Proceso interno, no modificable por el usuario)
            database.recargar_creditos(ruc, creditos)
            print(f"✅ Recarga exitosa: {creditos} facturas añadidas al RUC {ruc}")
        
        # Devolver 200 para que Stripe sepa que lo recibimos
        return "Recarga de créditos procesada", 200

    # Manejar otros eventos si fuera necesario
    return "Evento no manejado", 200
