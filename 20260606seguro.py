import subprocess
import re
from flask import Flask, request, jsonify, abort
from urllib.parse import urlparse
app = Flask(__name__)
# Catálogo cerrado de dominios de confianza para mitigar vectores de red (Lista 
Blanca)
TRUSTED_DOMAINS = ["api.internal-partner.com", "cdn.globalcore.financial"]
@app.route('/api/v1/process-report', methods=['POST'])
def process_report_secure():
 # =========================================================================
 # REMEDIACIÓN ALFA: Neutralización de Inyección de Comandos (CWE 78)
 # =========================================================================
 # SOURCE: Entrada de datos externa aislada
 file_identifier = request.json.get('fileId')
 
 if not file_identifier:
 abort(400, description="Parámetro 'fileId' faltante.")
 
 # VALIDACIÓN DE ENTRADA: Restricción estricta mediante expresiones regulares
 # Solo se admiten caracteres alfanuméricos puros para evitar metacaracteres de 
shell (; && |)
 if not re.match(r'^[a-zA-Z0-9_\-]+$', file_identifier):
 abort(400, description="Formato de identificador de archivo inválido.")
 
 # SINK SEGURO: Uso obligatorio del módulo subprocess con shell=False
 # Al pasar los argumentos en forma de lista, el sistema operativo desactiva el 
intérprete de shell,
 # tratando la entrada del usuario estrictamente como un argumento de texto 
literal.
 cmd_arguments = ["tar", "-czf", "/tmp/backup.tar.gz", 
f"/var/reports/{file_identifier}"]
 
 try:
 # Se ejecuta de forma segura impidiendo que el string inyecte nuevos 
comandos
 subprocess.run(cmd_arguments, check=True, shell=False, capture_output=True)
 except subprocess.CalledProcessError:
 abort(500, description="Error durante la ejecución del proceso de 
empaquetado.")
 # =========================================================================
 # REMEDIACIÓN BETA: Neutralización de Server-Side Request Forgery (CWE 918)
 # =========================================================================
 # SOURCE: Entrada de URL externa capturada
 callback_url = request.json.get('callbackUrl')
 
 if not callback_url:
 abort(400, description="Parámetro 'callbackUrl' faltante.")
 
 try:
 # Desglose sintáctico de la URL para analizar sus componentes individuales
 parsed_url = urlparse(callback_url)
 hostname = parsed_url.hostname
 
 # MITIGACIÓN MANDATORIA: Validación simétrica contra la lista blanca oficial
 # Bloquea de raíz el uso de localhost (127.0.0.1) o el endpoint de metadatos 
de AWS
 if hostname not in TRUSTED_DOMAINS:
 abort(403, description="Acceso denegado: Destino de red no autorizado en 
la política.")
 
 # SINK SEGURO: La petición saliente se procesa únicamente tras verificar la 
legitimidad del destino
 network_response = requests.get(callback_url, timeout=5)
 response_data = network_response.text[:200]
 
 except Exception:
 abort(500, description="Error de comunicación con el endpoint validado.")
 
 return jsonify({
 "status": "Procesamiento completado con éxito y verificado",
 "log_preview": response_data
 })
if __name__ == '__main__':
 app.run(host='0.0.0.0', port=5000)
