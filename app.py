# -*- coding: utf-8 -*-
"""
Backend API – Módulo INFORMES (Dashboard + Auditoría + Mapas + Logs + SIHOS)
Framework: Flask + SQLAlchemy + POO
"""

import os
import logging
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

# Importar Rutas
from routes.api_routes import api_bp
from routes.web_routes import web_bp
from config import Config

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s | [%(levelname)s] | %(message)s')
logger = logging.getLogger("INFORMES_MAIN")

# Inicialización (Usando carpetas estándar para HTML y Estáticos)
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# Registro de Blueprints (Módulos de rutas)
app.register_blueprint(api_bp)
app.register_blueprint(web_bp)

if __name__ == "__main__":
    port = int(os.getenv("PORT_INFORMES", 5001))
    logger.info(f"🚀 Iniciando servidor INFORMES ESE en puerto {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
