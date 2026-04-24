<div align="center">

# 📊 INFORMES & AUDITORÍA — Sistema de Gestión ESE

**Plataforma de inteligencia de negocios y auditoría clínica para Equipos Básicos de Salud (EBS) 2026**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Aiven-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Render](https://img.shields.io/badge/Deploy-Render.com-46E3B7?style=for-the-badge&logo=render&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-Gráficos-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)

</div>

---

## 📋 Tabla de Contenidos

- [Descripción General](#-descripción-general)
- [Arquitectura del Sistema](#-arquitectura-del-sistema)
  - [Diagrama ETL: Orquestador → Nube](#diagrama-1-etl-y-sincronización-orquestador--nube)
  - [Diagrama Web: Nube → Usuario](#diagrama-2-arquitectura-web-nube--usuario)
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

INFORMES ESE es una plataforma analítica y de auditoría de calidad de datos diseñada para monitorear, auditar y graficar en tiempo real el rendimiento de los Equipos Básicos de Salud (EBS) en los territorios y microterritorios. 

El sistema evalúa integralmente a los diferentes perfiles (Enfermería, Medicina, Psicología y Técnico Auxiliar) garantizando el cumplimiento de los lineamientos del Ministerio de Salud y Protección Social (Resolución 3280 de 2018).

### ¿Qué puede hacer el sistema?

- 📈 **Dashboard Global:** Visualización en tiempo real de métricas poblacionales, demográficas, caracterizaciones y avance general de los microterritorios.
- 🕵️ **Auditoría Individual:** Filtrado preciso por correo del encuestador y rango de fechas para evaluar su rendimiento exacto.
- 🏥 **Métricas por Perfil:** Diferenciación inteligente de intervenciones (ej. separando intervenciones generales de las específicas de Psicología).
- 📝 **Reportes Detallados y Errores:** Consolas de texto con los IDs de ficha exactos donde se cometieron errores o se registraron atenciones, listos para copiar al portapapeles.
- 🖨️ **Generación de Informes PDF:** Motor de impresión nativo (`@media print`) que transforma la vista web en un documento formal con membrete institucional.

---

## 🏗️ Arquitectura del Sistema

La plataforma funciona mediante un modelo **desacoplado**: un Orquestador local en Python consolida y evalúa la calidad de los datos crudos, para luego inyectar los resultados resumidos y limpios a PostgreSQL en la nube, donde Flask los distribuye al Frontend.

---

### Diagrama 1: ETL y Sincronización (Orquestador → Nube)

```mermaid
graph TD
    subgraph FUENTES["📂 Fuentes de Datos Crudos"]
        EpiCollect["📊 Archivos Excel<br/>Exportados de EpiCollect5"]
    end

    subgraph ORQUESTADOR["⚙️ Motor de Auditoría Local"]
        Main["🐍 Orquestador_Auditoria.py"]
        S1["Scripts de Limpieza<br/>(Desistimientos, Caracterización)"]
        S2["Scripts de Evaluación<br/>(PCC, PCF, Trámites)"]
    end

    subgraph NUBE["🟢 Base de Datos Nube (Aiven)"]
        CloudDB[("☁️ PostgreSQL")]
        T_Err["auditoria_errores_2026"]
        T_Tram["tramites_consolidados_2026"]
    end

    EpiCollect --> Main
    Main --> S1
    Main --> S2
    S1 --> Main
    S2 --> Main

    Main --"Consolida totales y errores\nSobreescribe tablas"--> CloudDB
    Main --"Sube detalles concatenados (|)"--> T_Tram
    Main --"Sube logs de inconsistencias"--> T_Err

    style FUENTES      fill:#fdf4ff,stroke:#c084fc,stroke-width:2px
    style ORQUESTADOR  fill:#eff6ff,stroke:#93c5fd,stroke-width:2px
    style NUBE         fill:#f0fdf4,stroke:#4ade80,stroke-width:2px
