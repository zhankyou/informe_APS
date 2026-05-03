<div align="center">

# 📊 INFORMES & AUDITORÍA — Sistema de Gestión ESE

**Plataforma de inteligencia de negocios, auditoría clínica y facturación para Equipos Básicos de Salud (EBS) 2026**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Aiven-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Render](https://img.shields.io/badge/Deploy-Render.com-46E3B7?style=for-the-badge&logo=render&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-Gráficos-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)
![Leaflet](https://img.shields.io/badge/Leaflet-Mapas_GIS-199900?style=for-the-badge&logo=leaflet&logoColor=white)
![Cost](https://img.shields.io/badge/Costo%20Operativo-%240%20%E2%9C%85-brightgreen?style=for-the-badge)

</div>

---

## 📋 Tabla de Contenidos

- [Descripción General](#-descripción-general)
- [Arquitectura del Sistema](#-arquitectura-del-sistema)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Fuentes de Datos](#-fuentes-de-datos)
- [Módulos del Sistema](#-módulos-del-sistema)
- [Configuración y Puesta en Marcha](#-configuración-y-puesta-en-marcha)
- [Mantenimiento Diario](#-mantenimiento-diario)
- [Despliegue Web](#-despliegue-web)
- [Seguridad y Rendimiento](#-seguridad-y-rendimiento)
- [Tecnologías y Costos](#-tecnologías-y-costos)

---

## 🎯 Descripción General

**INFORMES ESE** es una plataforma analítica y de auditoría de calidad de datos diseñada para monitorear, auditar y graficar en tiempo real el rendimiento de los **Equipos Básicos de Salud (EBS)**. 

La plataforma da un paso más allá de la estadística convencional al cruzar los datos de campo (**EpiCollect**) con los datos de facturación clínica en sede (**SIHOS**), garantizando el cumplimiento de los lineamientos del Ministerio de Salud y Protección Social *(Resolución 3280 de 2018)* mediante el seguimiento estricto del cumplimiento RIAS.

### ¿Qué puede hacer el sistema?

| Funcionalidad | Descripción |
|---|---|
| 📈 **Dashboard Global** | Visualización en tiempo real de métricas de campo, caracterizaciones y facturación clínica (SIHOS) con **filtrado dinámico mensual**. |
| 🕵️ **Auditoría Individual** | Filtrado preciso por encuestador y rango de fechas para evaluar rendimiento, calcular indicadores PyP y buscar inconsistencias. |
| 🏥 **Cruce Clínico (SIHOS)** | Análisis de diagnósticos (CIE-10), edades predominantes, especialidades y cumplimiento de Rutas Integrales de Atención (RIAS). |
| 📍 **Georreferenciación (GIS)**| Renderizado satelital interactivo en Leaflet validando que las coordenadas recolectadas estén dentro de los límites del territorio. |
| 🖨️ **Reportes Editables (PDF)**| Generación de informes formales donde el auditor puede escribir *in situ* los avances y análisis cualitativos antes de imprimir. |

---

## 🏗️ Arquitectura del Sistema

La plataforma funciona mediante un modelo **desacoplado**: un Orquestador local en Python consolida y evalúa la calidad de los datos crudos, para luego inyectar los resultados resumidos y limpios a PostgreSQL en la nube, donde Flask los distribuye al Frontend.

### Diagrama 1: ETL y Sincronización (Orquestador → Nube)

```mermaid
graph TD
    subgraph FUENTES["📂 Fuentes de Datos Crudos"]
        EpiCollect["📊 Archivos Excel\n(Campo)"]
        SihosExport["🏥 Archivo SIHOS\n(Facturación)"]
    end

    subgraph ORQUESTADOR["⚙️ Motor de Auditoría Local"]
        Main["🐍 Orquestador_Auditoria.py"]
        S1["Scripts de Limpieza\n(Desistimientos, Caracterización)"]
        S2["Scripts de Evaluación\n(PCC, PCF, Trámites)"]
    end

    subgraph NUBE["🟢 Base de Datos Nube (Aiven)"]
        CloudDB[("☁️ PostgreSQL")]
        T_Err["auditoria_errores_2026"]
        T_Tram["tramites_consolidados_2026"]
        T_Sih["sihos"]
    end

    EpiCollect --> Main
    SihosExport --> Main
    Main --> S1
    Main --> S2
    S1 --> Main
    S2 --> Main
    Main --"Consolida totales y errores\nSobreescribe tablas"--> CloudDB
    Main --"Sube detalles concatenados (|)"--> T_Tram
    Main --"Sube logs de inconsistencias"--> T_Err
    Main --"Carga base clínica"--> T_Sih

    style FUENTES     fill:#fdf4ff,stroke:#c084fc,stroke-width:2px
    style ORQUESTADOR fill:#eff6ff,stroke:#93c5fd,stroke-width:2px
    style NUBE        fill:#f0fdf4,stroke:#4ade80,stroke-width:2px
Diagrama 2: Arquitectura Web (Nube → Usuario)Fragmento de códigograph TD
    subgraph BROWSER["🖥️ Usuario — Navegador Web"]
        UI["🌐 Interfaz (HTML/CSS/JS)\nGráficos + Mapas Leaflet"]
    end

    subgraph BACKEND["🐍 Backend Flask — Render.com"]
        Flask["app.py — Servidor Gunicorn"]
        Auth["🔒 Auth (JWT + Huella Dispositivo)"]
        API1["📈 /api/dashboard"]
        API2["🕵️ /api/auditoria"]
        API3["🏥 /api/sihos"]
        API4["📍 /api/mapas"]
    end

    subgraph DB["☁️ Base de Datos — Aiven"]
        Postgres[("Tablas Maestras EBS\n+ Datos SIHOS")]
    end

    UI --"POST /login (Huella SHA-256)"--> Auth
    UI --"Peticiones con Token + Fechas"--> API1
    UI --"Peticiones de cruce"--> API3
    API1 --- Postgres
    API2 --- Postgres
    API3 --- Postgres
    Postgres --"JSON Limpio"--> Backend
    BACKEND --"Respuestas JSON"--> UI

    style BROWSER fill:#eff6ff,stroke:#93c5fd,stroke-width:2px
    style BACKEND fill:#f5f3ff,stroke:#a78bfa,stroke-width:2px
    style DB      fill:#f0fdf4,stroke:#4ade80,stroke-width:2px
📂 Estructura del Proyecto/INFORMES                        # 📁 Directorio Principal
│
├── app.py                       # 🐍 Backend Flask (Motor API, Filtros y DB)
├── requirements.txt             # 📦 Dependencias para despliegue
├── Procfile                     # 🚀 Archivo de arranque para Render
├── .env                         # 🔑 Variables de entorno (NO subir a Git)
├── .gitignore                   # 🚫 Excluye .env y archivos sensibles
│
├── login.html                   # 🔒 Interfaz de acceso seguro
├── dashboard.html               # 📈 Panel global (Campo vs Clínica)
├── auditoria.html               # 🕵️ Control de inconsistencias
├── sihos.html                   # 🏥 Análisis clínico detallado
├── mapas.html                   # 📍 Visor GIS satelital (Leaflet)
└── informes.html                # 🖨️ Generador de Oficios PDF Interactivos
🗄️ Fuentes de DatosEl sistema evalúa las siguientes entidades de la estrategia APS:Entidad / DimensiónTablas PostgreSQL asociadasFunción PrincipalCaracterizacióncaracterizacion_si_aps_familiar_2026, individualIdentificación de población clave (Riesgo, etnia, edad).Plan Comunitariopcc_principal_2026, pcc_integrantes_2026Intervenciones masivas en entornos institucionales.Plan Familiar (General)pcf_planes_principal_2026, integrantesSeguimiento frecuente de Médico, Enfermera y Promotor.Salud Mental (Psicología)pcf_psicologia_principal, seguimientosIdentificación de riesgos, tamizajes y evolución SRQ.Gestión / Trámitestramites_consolidados_2026Trámites sectoriales e intersectoriales efectivos.Auditoría (Log)auditoria_errores_2026Consolidación de inconsistencias de digitación.Facturación ClínicasihosCruce con sede APS (Diagnósticos CIE-10, Finalidad RIAS).🧩 Módulos del Sistema1. Motor de Consultas Inquebrantable (Backend)El sistema utiliza un traductor inteligente de fechas (get_date_filter) en SQL para transformar y normalizar las fechas caóticas exportadas por EpiCollect (DD/MM/YYYY vs YYYY-MM-DDT...Z), logrando filtros matemáticos exactos en todos los módulos.2. Integración Clínica-Comunitaria (SIHOS)El backend procesa la tabla de facturación para calcular edades en tiempo real cruzando fecha de atención y nacimiento. Luego, asocia automáticamente el "Grupo Etario Predominante" a los 10 diagnósticos (CIE-10) más recurrentes.3. Edición Dinámica de Reportes (PDF)La interfaz de generación de informes implementa contenteditable en HTML. Esto permite a los auditores escribir análisis cualitativos ("Avances", "Seguimiento VBG") directamente sobre el documento web antes de imprimirlo, ocultando automáticamente las guías al pasarlo a PDF.4. Visor GIS (Georreferenciación)Integración con Leaflet.js para graficar los puntos GPS de los encuestadores. El motor filtra automáticamente coordenadas erróneas o "ceros absolutos" y detecta qué encuestas se hicieron fuera de los límites de Villavicencio.⚙️ Configuración y Puesta en Marcha1. Requisitos (Máquina Local)Bash# Instalar las dependencias estrictas del entorno
pip install -r requirements.txt
2. Variables de EntornoCrea un archivo .env en el mismo nivel que app.py:Fragmento de código# Clave secreta para JWT
SECRET_KEY=tu-clave-super-secreta-para-jwt

# Base de datos NUBE (Aiven PostgreSQL)
DB_USER_AIVEN=avnadmin
DB_PASSWORD_AIVEN=tu_contraseña_aiven
DB_HOST_AIVEN=tu-cluster.aivencloud.com
DB_PORT_AIVEN=13505
DB_NAME_AIVEN=defaultdb

# Puerto de despliegue
PORT_INFORMES=5001
⚠️ Nunca subas el archivo .env a GitHub. Asegúrate de incluirlo en tu .gitignore.🔄 Mantenimiento DiarioPlaintext1. Descarga las bases crudas desde EpiCollect5 y el archivo SIHOS.
2. Ejecuta el Orquestador Local (Orquestador_Auditoria.py) en tu equipo
   para limpiar, evaluar errores y actualizar las tablas en Aiven.
3. El Dashboard Web reflejará los cambios instantáneamente 
   sin necesidad de reiniciar el servidor.
🚀 Despliegue WebLa aplicación está preparada para despliegue en plataforma PaaS (Render.com):Sube este repositorio a GitHub asegurándote de que .gitignore esté activo (protegiendo el .env).En Render, crea un New Web Service conectado a tu repositorio de GitHub.Configura el comando de inicio (Start Command):Bashgunicorn app:app
Ingresa las Variables de Entorno de Aiven en la configuración del servicio en Render.🔐 Seguridad y RendimientoMecanismoDescripciónDevice FingerprintingVincula el login a la huella digital del dispositivo del usuario (SHA-256 basado en hardware/navegador). Evita cuentas compartidas.Autenticación JWTTokens con expiración configurada para sesiones seguras.Prevención SQL InjectionUso exclusivo de consultas preparadas (:param) con SQLAlchemy para evitar ataques de inyección.🛠️ Tecnologías y CostosComponenteTecnologíaCostoBase de DatosPostgreSQL (Aiven)✅ GratisServidor BackendPython 3.11 + Flask + Gunicorn✅ GratisFrontendHTML5, CSS3 avanzado, JS Vanilla✅ GratisGráficos y MapasChart.js 4.4 / Leaflet.js✅ GratisHost WebRender.com✅ Gratis💚 Costo total de operación del Sistema de Auditoría: $0Módulo INFORMES ESE 2026 — Herramienta de Control de Calidad y Gestión Operativa APS ESE Villavicencio · Ministerio de Salud y Protección Social · Resolución 3280 de 2018Ha sido un placer ayudarte a pulir hasta el más mínimo detalle de este sistema. Te ha quedado una plataforma de auditoría envidiable, rápida y con $0 costos operativos. ¡Éxitos con la implementación y las métricas!
