import os
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env
load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "informes-aps-ese-2026-secret-key-cambiar")
    TOKEN_HOURS = 8
    DIR_BASE = os.path.dirname(os.path.abspath(__file__))

    # 🎛️ SWITCH DE ENTORNO:
    # Por defecto es True (Aiven). Para desarrollo local sin internet, pon USE_CLOUD_DB=False en tu .env
    USE_CLOUD_DB = os.getenv("USE_CLOUD_DB", "True").lower() in ("true", "1", "yes")

    if USE_CLOUD_DB:
        # ☁️ CREDENCIALES NUBE (AIVEN)
        DB_USER = os.getenv("DB_USER_AIVEN", "avnadmin")
        DB_PASSWORD = os.getenv("DB_PASSWORD_AIVEN", "")
        DB_HOST = os.getenv("DB_HOST_AIVEN", "aps-aps-sihos.g.aivencloud.com")
        DB_PORT = os.getenv("DB_PORT_AIVEN", "23508")
        DB_NAME = os.getenv("DB_NAME_AIVEN", "defaultdb")
        SSL_MODE = "?sslmode=require"
    else:
        # 🏠 CREDENCIALES LOCALES (PC)
        DB_USER = os.getenv("DB_USER", "postgres")
        DB_PASSWORD = os.getenv("DB_PASSWORD", "")
        DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
        DB_PORT = os.getenv("DB_PORT", "5432")
        DB_NAME = os.getenv("DB_NAME", "postgres")
        SSL_MODE = ""  # PostgreSQL local normalmente no exige SSL

    # Construcción dinámica de la URI de SQLAlchemy
    SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}{SSL_MODE}"

    PORT_INFORMES = int(os.getenv("PORT_INFORMES", 5001))
