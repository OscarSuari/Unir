import os  # REINTRODUCCIÓN: Se requiere os para el sumidero vulnerable os.system
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/v1/process-report', methods=['POST'])
def process_report_vulnerable():
    # =========================================================================
    # VECTOR ALFA CONTAMINADO: Inyección de Comandos (CWE 78)
    # =========================================================================
    # SOURCE: Entrada de datos externa leída directamente del JSON
    file_identifier = request.json.get('fileId')
    
    if not file_identifier:
        return jsonify({"error": "Parámetro 'fileId' faltante."}), 400
        
    # ELIMINACIÓN DE LA FRONTERA DE CONFIANZA:
    # Se eliminó por completo el bloque re.match que filtraba caracteres especiales.
    
    # SINK VULNERABLE: Concatenación directa dentro de una cadena destinada a la Shell
    command = f"tar -czf /tmp/backup.tar.gz /var/reports/{file_identifier}"
    
    # os.system invoca un intérprete (/bin/sh o cmd) que interpretará metacaracteres (; && |)
    os.system(command)

    # =========================================================================
    # VECTOR BETA CONTAMINADO: Server-Side Request Forgery (CWE 918)
    # =========================================================================
    # SOURCE: Entrada de URL sin verificar
    callback_url = request.json.get('callbackUrl')
    
    # REINTRODUCCIÓN DE PROXY CIEGO:
    # Se eliminó el desglose sintáctico (urlparse) y la validación por lista blanca.
    # El bloque try/except general ya no intercepta de forma incorrecta las excepciones lógicas.
    if callback_url:
        try:
            # SINK VULNERABLE: requests.get procesa cualquier dirección arbitraria provista por el cliente
            # Se eliminó el timeout para permitir ataques de denegación de servicio por conexiones colgadas.
            network_response = requests.get(callback_url)
            response_data = network_response.text[:200]
        except Exception as e:
            response_data = f"Fallo al conectar con el destino: {str(e)}"
    else:
        response_data = "No se solicitó callback."
        
    return jsonify({
        "origen": "CÓDIGO CONTAMINADO",
        "status": "Procesamiento completado",
        "log_preview": response_data
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
