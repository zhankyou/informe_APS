// static/js/dashboard.js

let _datosDashboard = null;
let isSearching = false;
const chartInstances = {};
const PALETTE = ['#0a1f3d', '#00b09b', '#f0a500', '#6c3fc5', '#e53935','#1e9c6e','#00d4b8','#f5a623','#8b5cf6','#ef4444'];

function buildChart(canvasId, type, labels, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (chartInstances[canvasId]) chartInstances[canvasId].destroy();

    chartInstances[canvasId] = new Chart(ctx, {
        type,
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: type === 'doughnut' ? PALETTE : PALETTE.map(c => c + 'cc'),
                borderColor: type === 'doughnut' ? PALETTE.map(c => c + '33') : PALETTE,
                borderWidth: type === 'bar' ? 0 : 2,
                borderRadius: type === 'bar' ? 6 : 0,
            }],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: type === 'doughnut', position: 'right', labels: { font: { family: 'Sora', size: 10 }, boxWidth: 10, padding: 8 } },
                tooltip: { bodyFont: { family: 'Sora', size: 11 }, titleFont: { family: 'Sora', size: 12, weight: '600' } },
            },
            scales: type === 'bar' ? {
                y: { beginAtZero: true, ticks: { font: { family: 'Sora', size: 10 } } },
                x: { ticks: { font: { family: 'Sora', size: 9 }, maxRotation: 40 } },
            } : {},
            ...options,
        },
    });
}

function buildPrintChart(canvasId, type, labels, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (chartInstances[canvasId]) chartInstances[canvasId].destroy();
    chartInstances[canvasId] = new Chart(ctx, {
      type: type,
      data:{ labels, datasets:[{ data, backgroundColor: PALETTE, borderColor: '#fff', borderWidth: 1 }] },
      options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display: false }, tooltip: { enabled: false } }, animation: false }
    });
}

function getMiniTable(labels, data) {
    let tbody = '';
    labels.forEach((lbl, idx) => {
      let c = PALETTE[idx % PALETTE.length];
      tbody += `<tr><td style="width:12px; padding:3px;"><div style="width:10px; height:10px; background:${c};"></div></td><td style="font-size:7.5pt; padding:3px;">${lbl}</td><td style="font-size:7.5pt; font-weight:bold; text-align:right; padding:3px;">${fmt(data[idx])}</td></tr>`;
    });
    return `<table class="mini-legend-table">${tbody}</table>`;
}

// ── CARGAR DATOS DEL DASHBOARD ──
async function loadDashboard() {
    if (isSearching) return;
    const monthFilter = document.getElementById('filterMonth').value;
    let urlExt = '';
    if (monthFilter) {
        const [y, m] = monthFilter.split('-');
        const lastDay = new Date(y, m, 0).getDate();
        urlExt = `?fecha_inicio=${y}-${m}-01&fecha_fin=${y}-${m}-${lastDay}`;
    }

    isSearching = true;
    document.getElementById('btnRefresh').disabled = true;
    document.getElementById('loadingOverlay').style.display = 'flex';
    document.getElementById('btnPrint').style.display = 'none';

    try {
        const token = localStorage.getItem('informes_token');
        const [respDash, respSihos] = await Promise.all([
            fetch(`${API_BASE}/api/dashboard${urlExt}`, { headers: {'Authorization': 'Bearer ' + token} }),
            fetch(`${API_BASE}/api/sihos${urlExt}`, { headers: {'Authorization': 'Bearer ' + token} })
        ]);

        if (respDash.status === 401) { logout(); return; }

        const d = await respDash.json();
        let s = null;
        if (respSihos.ok) {
            const dataSihos = await respSihos.json();
            if(!dataSihos.error) s = dataSihos;
        }

        _datosDashboard = { ...d, sihos: s };

        document.getElementById('sec-sihos').style.display = 'block';
        setVal('sihos-total', s ? s.resumen?.total_facturaciones : 0);
        setVal('sihos-rias', s ? s.indicadores?.total_rias : 0);
        setVal('sihos-med', s ? s.indicadores?.pyp_medicina : 0);
        setVal('sihos-enf', s ? s.indicadores?.pyp_enfermeria : 0);
        setVal('sihos-psi', s ? s.indicadores?.salud_mental : 0);

        if(s && s.demografia?.genero && s.demografia.genero.length > 0) buildChart('chartSihosGenero', 'doughnut', s.demografia.genero.map(x=>x.label), s.demografia.genero.map(x=>x.total));
        else buildChart('chartSihosGenero', 'doughnut', ['Sin datos'], [1]);

        if(s && s.clinico?.tipo_servicio && s.clinico.tipo_servicio.length > 0) buildChart('chartSihosServicio', 'doughnut', s.clinico.tipo_servicio.map(x=>x.label), s.clinico.tipo_servicio.map(x=>x.total));
        else buildChart('chartSihosServicio', 'doughnut', ['Sin datos'], [1]);

        const now = new Date().toLocaleString('es-CO', { dateStyle: 'long', timeStyle: 'short' });
        document.getElementById('topbarFecha').textContent = 'Última actualización: ' + now + (monthFilter ? ` (Filtrado: ${monthFilter})` : '');

        setVal('d-total', d.desistimientos?.total); setVal('d-error', d.desistimientos?.con_error);
        setVal('pcc-planes', d.pcc?.planes); setVal('pcc-integ', d.pcc?.integrantes); setVal('pcc-error', d.pcc?.con_error);

        const ca = d.caracterizacion || {};
        setVal('ca-familias', ca.familias); setVal('ca-fam-dup', ca.familias_duplicadas);
        setVal('ca-individuos', ca.individuos); setVal('ca-ind-dup', ca.individuos_duplicadas);
        setVal('ca-sinaseg', ca.sin_aseguramiento); setVal('ca-gestantes', ca.gestantes);
        setVal('ca-menores5', ca.menores_5); setVal('ca-adultos60', ca.adultos_60);
        setVal('ca-victimas', ca.victimas_conflicto); setVal('ca-etnica', ca.poblacion_etnica);
        setVal('ca-err-fam', ca.error_familiar); setVal('ca-err-ind', ca.error_individual);
        setVal('ca-disc', ca.discapacidad_total);

        const pctCon = ca.etnia_con_pct || 0;
        const pctSin = ca.etnia_sin_pct || 0;
        document.getElementById('etnia-fill-bar').style.width = pctCon + '%';
        document.getElementById('etnia-con-label').textContent = `${pctCon}% con pertenencia étnica (${fmt(ca.etnia_con_total)})`;
        document.getElementById('etnia-sin-label').textContent = `${pctSin}% sin pertenencia étnica`;

        const tf = ca.tipo_familia || []; buildChart('chartTipoFamilia', 'doughnut', tf.map(x => x.label), tf.map(x => x.total));
        const es = ca.estrato || []; buildChart('chartEstrato', 'bar', es.map(x => x.label), es.map(x => x.total));
        const ed = ca.nivel_educativo || []; buildChart('chartEducacion', 'bar', ed.map(x => x.label), ed.map(x => x.total));
        const disc = ca.discapacidades_chart || []; buildChart('chartDiscapacidad', 'bar', disc.map(x => x.label), disc.map(x => x.total));

        setVal('ht-caract', d.hogares_territorio?.total_caract);
        setVal('ht-pcf', d.hogares_territorio?.total_pcf);
        setVal('ht-conc', d.hogares_territorio?.total_concertados);
        document.getElementById('ht-conc-pct').textContent = (d.hogares_territorio?.total_caract > 0 ? ((d.hogares_territorio.total_concertados / d.hogares_territorio.total_caract) * 100).toFixed(1) : 0) + '% Cobertura Efectiva';

        const ht = d.hogares_territorio?.desglose || [];
        const ctxHt = document.getElementById('chartHogaresTerritorio');
        if(ctxHt) {
            if(chartInstances['chartHogaresTerritorio']) chartInstances['chartHogaresTerritorio'].destroy();
            chartInstances['chartHogaresTerritorio'] = new Chart(ctxHt.getContext('2d'), {
                type: 'bar', data: { labels: ht.map(x => x.label), datasets: [ {label: 'Caracterizados', data: ht.map(x => x.caract), backgroundColor: '#6c3fc5', borderRadius: 3}, {label: 'Planes Cuidado', data: ht.map(x => x.pcf), backgroundColor: '#00b09b', borderRadius: 3} ] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { tooltip:{callbacks:{label:c=>` ${c.dataset.label}: ${c.parsed.y.toLocaleString('es-CO')}`}} }, scales: { x: { ticks: { font: { size: 9 }, maxRotation: 40 } } } }
            });
        }

        const tbodyHt = document.querySelector('#tablaDesgloseHogares tbody');
        tbodyHt.innerHTML = '';
        if(ht.length === 0) {
            tbodyHt.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem;">Sin datos en este periodo</td></tr>';
        } else {
            ht.forEach(item => {
                let color = item.porcentaje >= 80 ? 'var(--green)' : (item.porcentaje >= 40 ? 'var(--gold)' : 'var(--red)');
                tbodyHt.innerHTML += `<tr><td style="font-weight:600; font-size: 0.8rem;">${item.label}</td><td style="text-align:center; font-family:monospace; font-size:0.95rem;">${fmt(item.caract)}</td><td style="text-align:center; font-family:monospace; font-size:0.95rem; font-weight:700; color:var(--teal);">${fmt(item.pcf)}</td><td style="text-align:center; font-family:monospace; font-size:0.95rem; color:var(--navy);">${fmt(item.concertados)}</td><td style="text-align:center;"><span class="res-badge" style="color:${color}; background:${color}1a;">${item.porcentaje}%</span></td></tr>`;
            });
        }

        setVal('pcf-fam', d.pcf?.familias_intervenidas); setVal('pcf-fam-dup', d.pcf?.familias_duplicadas);
        setVal('pcf-integ', d.pcf?.integrantes_intervenidos); setVal('pcf-int-dup', d.pcf?.integrantes_duplicados);
        setVal('psi-interv', d.pcf_psicologia?.intervenciones_familiares); setVal('psi-fam-dup', d.pcf_psicologia?.familias_duplicadas);
        setVal('psi-integ', d.pcf_psicologia?.integrantes); setVal('psi-seg', d.pcf_psicologia?.seguimientos);

        setVal('tr-registros', d.tramites?.total_registros); setVal('tr-familias', d.tramites?.total_familias);
        setVal('tr-total', d.tramites?.total); setVal('tr-resol', d.tramites?.resolutivos); setVal('tr-error', d.tramites?.con_error);

        const tr = d.tramites?.por_tipo || [];
        buildChart('chartTramites', 'bar', tr.map(x => x.label), tr.map(x => x.total));

        const tbodyTram = document.querySelector('#tablaDesgloseTramites tbody');
        const elTot = document.getElementById('tdTotal'); const elRes = document.getElementById('tdRes'); const elPct = document.getElementById('tdPct');
        tbodyTram.innerHTML = ''; let sumTot = 0, sumRes = 0;

        if (tr.length === 0) {
            tbodyTram.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:2rem;">Sin datos en este periodo</td></tr>';
            elTot.textContent = '0'; elRes.textContent = '0'; elPct.textContent = '0%';
        } else {
            tr.forEach(item => {
                sumTot += item.total; sumRes += item.resueltos;
                let color = item.porcentaje === 100 ? 'var(--green)' : (item.porcentaje === 0 ? 'var(--gold)' : 'var(--text)');
                tbodyTram.innerHTML += `<tr><td style="font-weight:600;">${item.label}</td><td style="text-align:center; font-family:monospace; font-size:1rem;">${fmt(item.total)}</td><td style="text-align:center; font-family:monospace; font-size:1rem; font-weight:700; color:var(--navy);">${fmt(item.resueltos)}</td><td style="text-align:center;"><span class="res-badge" style="color:${color}; background:${color}1a;">${item.porcentaje}%</span></td></tr>`;
            });
            elTot.textContent = fmt(sumTot); elRes.textContent = fmt(sumRes);
            elPct.textContent = (sumTot > 0 ? ((sumRes / sumTot) * 100).toFixed(1) : 0) + '%';
        }

        // MOSTRAR BOTÓN DE IMPRESIÓN
        document.getElementById('btnPrint').style.display = 'flex';

    } catch (err) {
        alert(`⚠️ Fallo en la consulta.\nRevisa la conexión con el servidor.`);
        document.getElementById('topbarFecha').textContent = '⚠️ Error al cargar datos.';
    } finally {
        isSearching = false;
        document.getElementById('btnRefresh').disabled = false;
        document.getElementById('loadingOverlay').style.display = 'none';
    }
}

// ── FUNCIÓN PARA IMPRIMIR PDF PERFECTO ──
function getChartImageHTML(canvasId) {
    const canvas = document.getElementById(canvasId);
    return canvas ? `<img src="${canvas.toDataURL('image/png')}" class="rp-chart-img" />` : '';
}

function generarYImprimir() {
    if (!_datosDashboard) return;

    // Mostramos overlay para evitar clics dobles mientras renderiza el PDF
    document.getElementById('loadingOverlay').style.display = 'flex';
    document.querySelector('.loading-text').textContent = "Preparando documento PDF...";

    setTimeout(() => {
        const d = _datosDashboard; const ca = d.caracterizacion || {}; const s = d.sihos || null;
        const userInfo = JSON.parse(localStorage.getItem('informes_user') || '{}');
        const hoy = new Date().toLocaleDateString('es-CO', { dateStyle:'full' });

        let chartDiscHtml = getChartImageHTML('chartDiscapacidad') ? `<div style="text-align:center; margin-top: 10pt;"><div class="rp-sub-title-indicador">Frecuencia de Tipos de Discapacidad</div>${getChartImageHTML('chartDiscapacidad')}</div>` : '';

        // HOGARES
        let filasHogares = '';
        const ht = d.hogares_territorio?.desglose || [];
        if (ht.length > 0) {
            ht.forEach(item => {
                let color = item.porcentaje >= 80 ? '#1e9c6e' : (item.porcentaje >= 40 ? '#f0a500' : '#e53935');
                filasHogares += `<tr><td>${item.label}</td><td class="td-num">${fmt(item.caract)}</td><td class="td-num" style="color:#00b09b;">${fmt(item.pcf)}</td><td class="td-num" style="color:#0a1f3d;">${fmt(item.concertados)}</td><td class="td-num" style="color:${color}; font-weight:bold;">${item.porcentaje}%</td></tr>`;
            });
        } else { filasHogares = `<tr><td colspan="5" style="text-align:center; color:#888; height:20pt;">Sin datos de hogares en este periodo</td></tr>`; }

        // TRAMITES
        let filasTramites = ''; let sumaTram = 0, sumaRes = 0, sumaPend = 0;
        if (d.tramites && d.tramites.por_tipo && d.tramites.por_tipo.length > 0) {
            d.tramites.por_tipo.forEach(item => {
                sumaTram += item.total || 0; sumaRes += item.resueltos || 0; sumaPend += item.pendientes || 0;
                filasTramites += `<tr><td>${item.label}</td><td class="td-num">${fmt(item.total)}</td><td class="td-num" style="color:#1e9c6e;">${fmt(item.resueltos)}</td><td class="td-num" style="color:#f0a500;">${fmt(item.pendientes)}</td><td class="td-num" style="color:#0a1f3d;">${item.porcentaje||0}%</td></tr>`;
            });
            filasTramites += `<tr style="background:#dce9f5;"><td style="text-align:right; font-weight:bold; color:#003366;">TOTAL DESGLOSADO</td><td class="td-num" style="font-size:9.5pt;">${fmt(sumaTram)}</td><td class="td-num" style="font-size:9.5pt; color:#1e9c6e;">${fmt(sumaRes)}</td><td class="td-num" style="font-size:9.5pt; color:#f0a500;">${fmt(sumaPend)}</td><td class="td-num" style="font-size:9.5pt; color:#0a1f3d;">${sumaTram > 0 ? (sumaRes / sumaTram * 100).toFixed(1) : 0}%</td></tr>`;
        } else { filasTramites = `<tr><td colspan="5" style="text-align:center; color:#888; height:20pt;">Sin trámites en este periodo</td></tr>`; }

        // SIHOS
        let filasDiagnosticos = '';
        if (s && s.clinico && s.clinico.diagnosticos && s.clinico.diagnosticos.length > 0) {
            s.clinico.diagnosticos.slice(0, 7).forEach(diag => {
                let etario = ((diag.grupo_etario) || 'Sin Datos').replace(/^\d+\.\s*/, '');
                filasDiagnosticos += `<tr><td class="ind-strong" style="font-size:7.5pt;">${diag.label}</td><td class="ind-result">${fmt(diag.total)}</td><td style="font-size:8pt; text-align:center;">${etario}</td></tr>`;
            });
        } else { filasDiagnosticos = `<tr><td colspan="3" style="text-align:center; color:#888; height:30pt;">No hay diagnósticos registrados</td></tr>`; }

        // Renderizar los gráficos temporales de SIHOS para impresión
        if (s && s.resumen && s.resumen.total_facturaciones > 0) {
            buildPrintChart('printChartGeneroGlobal', 'doughnut', s.demografia.genero.map(x=>x.label), s.demografia.genero.map(x=>x.total));
            buildPrintChart('printChartServicioGlobal', 'doughnut', s.clinico.tipo_servicio.map(x=>x.label), s.clinico.tipo_servicio.map(x=>x.total));
        } else {
            buildPrintChart('printChartGeneroGlobal', 'doughnut', ['Sin datos'], [1]);
            buildPrintChart('printChartServicioGlobal', 'doughnut', ['Sin datos'], [1]);
        }

        let tableGen = s && s.demografia?.genero?.length > 0 ? getMiniTable(s.demografia.genero.map(x=>x.label), s.demografia.genero.map(x=>x.total)) : '<div style="color:#888; font-size:8pt;">Sin datos</div>';
        let tableSrv = s && s.clinico?.tipo_servicio?.length > 0 ? getMiniTable(s.clinico.tipo_servicio.map(x=>x.label), s.clinico.tipo_servicio.map(x=>x.total)) : '<div style="color:#888; font-size:8pt;">Sin datos</div>';

        // CONSTRUCCIÓN DEL HTML PARA EL PDF
        const html = `
          <div class="rp-header-inst">
            <div class="rp-header-top">MINISTERIO DE SALUD Y PROTECCIÓN SOCIAL · ESE VILLAVICENCIO · EQUIPOS BÁSICOS DE SALUD</div>
            <div class="rp-header-info">
              <div style="width: 100px;"><img src="/static/img/logo-ese.png" style="width:100%;"/></div>
              <div class="rp-address-cell">Carrera 42 N° 33–24 Barzal Alto, Villavicencio — Meta<br/>Conmutador: (098) 6614100<br/>NIT: 822.002.459 - Res. 763/2025</div>
              <div style="width: 140px;"><img src="/static/img/logo-aps.png" style="width:100%;"/></div>
            </div>
          </div>

          <div class="rp-title-block">
            <div class="rp-title-main">Reporte Global de Dashboard</div>
            <div class="rp-title-sub">Consolidado general de la operación de los Equipos Básicos de Salud</div>
          </div>

          <table class="rp-id-table"><tr><td>Generado por:</td><td>${userInfo.nombre||'Administrador'}</td><td>Fecha de generación:</td><td>${hoy}</td></tr></table>

          <div class="rp-section">
            <div class="rp-section-title">1. RESUMEN GLOBAL EN CAMPO</div>
            <table class="rp-table">
              <tr><th>Módulo</th><th style="width:110pt;text-align:right;">Total Registros</th><th style="width:110pt;text-align:right;">Errores Detectados</th></tr>
              <tr><td>Desistimientos</td><td class="td-num">${fmt(d.desistimientos?.total)}</td><td class="td-num" style="color:#c0392b;">${fmt(d.desistimientos?.con_error)}</td></tr>
              <tr><td>Plan Cuidado Comunitario (Planes)</td><td class="td-num">${fmt(d.pcc?.planes)}</td><td class="td-num" style="color:#c0392b;">${fmt(d.pcc?.con_error)}</td></tr>
              <tr><td>Caracterización Familiar</td><td class="td-num">${fmt(ca.familias)}</td><td class="td-num" style="color:#c0392b;">${fmt(ca.error_familiar)}</td></tr>
              <tr><td>Caracterización Individual</td><td class="td-num">${fmt(ca.individuos)}</td><td class="td-num" style="color:#c0392b;">${fmt(ca.error_individual)}</td></tr>
              <tr><td>Trámites Gestionados</td><td class="td-num">${fmt(d.tramites?.total)}</td><td class="td-num" style="color:#c0392b;">${fmt(d.tramites?.con_error)}</td></tr>
            </table>
          </div>

          <div class="rp-section page-break">
            <div class="rp-section-title">2. POBLACIÓN CLAVE Y DEMOGRAFÍA</div>
            <table class="rp-table">
              <tr><th>Indicador Demográfico</th><th style="width:110pt;text-align:right;">Total Identificados</th></tr>
              <tr><td>Familias sin aseguramiento en salud</td><td class="td-num">${fmt(ca.sin_aseguramiento)}</td></tr>
              <tr><td>Gestantes</td><td class="td-num">${fmt(ca.gestantes)}</td></tr>
              <tr><td>Menores de 5 años</td><td class="td-num">${fmt(ca.menores_5)}</td></tr>
              <tr><td>Adultos mayores (60+)</td><td class="td-num">${fmt(ca.adultos_60)}</td></tr>
              <tr><td>Víctimas del conflicto armado</td><td class="td-num">${fmt(ca.victimas_conflicto)}</td></tr>
              <tr><td style="background:#e6f7f5;">Población con discapacidad</td><td class="td-num" style="background:#e6f7f5;">${fmt(ca.discapacidad_total)}</td></tr>
              <tr><td>Población con pertenencia étnica</td><td class="td-num">${fmt(ca.etnia_con_total)} personas (${ca.etnia_con_pct||0}%)</td></tr>
            </table>
            ${chartDiscHtml}
          </div>

          <div class="rp-section">
            <div class="rp-section-title" style="background:#00b09b;">3. COBERTURA DE HOGARES POR TERRITORIO</div>
            <table class="rp-table" style="margin-bottom:10pt;">
              <tr><th>Hogares Caracterizados</th><th style="text-align:right;">Hogares con Plan de Cuidado</th><th style="text-align:right;">Hogares Concertados</th><th style="text-align:right;">Cobertura Efectiva Global</th></tr>
              <tr><td class="td-num" style="text-align:left;">${fmt(d.hogares_territorio?.total_caract)}</td><td class="td-num" style="color:#00b09b;">${fmt(d.hogares_territorio?.total_pcf)}</td><td class="td-num" style="color:#0a1f3d;">${fmt(d.hogares_territorio?.total_concertados)}</td><td class="td-num" style="color:#1e9c6e; font-size:10pt;">${d.hogares_territorio?.total_caract > 0 ? ((d.hogares_territorio.total_concertados / d.hogares_territorio.total_caract) * 100).toFixed(1) : 0}%</td></tr>
            </table>
            <div class="rp-sub-title-indicador">3.1 Desglose por Territorio y Microterritorio</div>
            <table class="rp-table"><thead><tr><th>Territorio / Microterritorio</th><th style="width:65pt;text-align:right;">Caracterizados</th><th style="width:65pt;text-align:right;">Planes Cuidado</th><th style="width:65pt;text-align:right;">Concertados</th><th style="width:55pt;text-align:right;">Cobertura</th></tr></thead><tbody>${filasHogares}</tbody></table>
          </div>

          <div class="rp-section page-break">
            <div class="rp-section-title">4. PLANES DE CUIDADO FAMILIAR (PCF)</div>
            <table class="rp-table">
              <tr><th>Tipo de Intervención</th><th style="width:110pt;text-align:right;">Familias</th><th style="width:110pt;text-align:right;">Integrantes</th></tr>
              <tr><td>General (Promotor, Medicina, Enfermería)</td><td class="td-num">${fmt(d.pcf?.familias_intervenidas)}</td><td class="td-num">${fmt(d.pcf?.integrantes_intervenidos)}</td></tr>
              <tr><td>Salud Mental (Psicología)</td><td class="td-num">${fmt(d.pcf_psicologia?.intervenciones_familiares)}</td><td class="td-num">${fmt(d.pcf_psicologia?.integrantes)}</td></tr>
            </table>
            <table class="rp-table" style="margin-top:4pt;"><tr><td><strong>Total de Seguimientos Psicológicos Realizados</strong></td><td class="td-num">${fmt(d.pcf_psicologia?.seguimientos)}</td></tr></table>
          </div>

          <div class="rp-section">
            <div class="rp-section-title">5. PERFIL SOCIAL DEL TERRITORIO</div>
            <div class="rp-charts-container">
               <div style="flex:1; text-align:center;"><div class="rp-sub-title-indicador">Tipo Familia</div>${getChartImageHTML('chartTipoFamilia')}</div>
               <div style="flex:1; text-align:center;"><div class="rp-sub-title-indicador">Estrato</div>${getChartImageHTML('chartEstrato')}</div>
               <div style="flex:1; text-align:center;"><div class="rp-sub-title-indicador">Educación</div>${getChartImageHTML('chartEducacion')}</div>
            </div>
          </div>

          <div class="rp-section page-break">
            <div class="rp-section-title">6. GESTIÓN DE TRÁMITES</div>
            <table class="rp-table" style="margin-bottom:10px;">
              <tr><th>Indicador</th><th style="width:90pt;text-align:right;">Total</th></tr>
              <tr><td>Personas con trámite (Registros únicos)</td><td class="td-num">${fmt(d.tramites?.total_registros)}</td></tr>
              <tr><td>Familias con trámites realizados</td><td class="td-num">${fmt(d.tramites?.total_familias)}</td></tr>
              <tr><td>Total trámites gestionados</td><td class="td-num">${fmt(d.tramites?.total)}</td></tr>
              <tr><td>Trámites resolutivos (efectivos)</td><td class="td-num">${fmt(d.tramites?.resolutivos)}</td></tr>
            </table>
            <div class="rp-sub-title-indicador" style="margin-top: 10pt;">6.1 Desglose por Tipo de Trámite</div>
            <table class="rp-table"><thead><tr><th>Tipo de Trámite</th><th style="width:60pt;text-align:right;">Total Realizados</th><th style="width:50pt;text-align:right;">Resueltos</th><th style="width:50pt;text-align:right;">Pendientes</th><th style="width:60pt;text-align:right;">% Resolutivos</th></tr></thead><tbody>${filasTramites}</tbody></table>
            <div style="text-align: center; margin-top:5pt;">${getChartImageHTML('chartTramites')}</div>
          </div>

          <div class="rp-section">
            <div class="rp-section-title" style="background:#6c3fc5;">7. ANÁLISIS DE FACTURACIÓN CLÍNICA GLOBAL (SIHOS)</div>
            <table class="rp-table">
              <tr><th>Indicador Clínico</th><th style="width:90pt;text-align:right;">Cantidad Global</th></tr>
              <tr><td>Total Facturaciones / Atenciones Médicas</td><td class="td-num">${fmt(s ? s.resumen?.total_facturaciones : 0)}</td></tr>
              <tr><td>Consultas Promoción y Mantenimiento (Medicina)</td><td class="td-num">${fmt(s ? s.indicadores?.pyp_medicina : 0)}</td></tr>
              <tr><td>Consultas Promoción y Mantenimiento (Enfermería)</td><td class="td-num">${fmt(s ? s.indicadores?.pyp_enfermeria : 0)}</td></tr>
              <tr><td>Consultas de Salud Mental y Psicología</td><td class="td-num">${fmt(s ? s.indicadores?.salud_mental : 0)}</td></tr>
              <tr style="background:#ede8fb;"><td><strong>TOTAL CUMPLIMIENTO RIAS (Sede APS)</strong></td><td class="td-num" style="color:#6c3fc5;">${fmt(s ? s.indicadores?.total_rias : 0)}</td></tr>
            </table>
            <div style="display:flex; justify-content:space-between; gap:20pt; margin-top:10pt;">
              <div style="flex:1;"><div class="rp-sub-title-indicador">Distribución por Género</div><div class="chart-box"><div class="donut-wrapper"><canvas id="printChartGeneroGlobal"></canvas></div><div class="legend-wrapper">${tableGen}</div></div></div>
              <div style="flex:1;"><div class="rp-sub-title-indicador">Tipo de Servicio Global</div><div class="chart-box"><div class="donut-wrapper"><canvas id="printChartServicioGlobal"></canvas></div><div class="legend-wrapper">${tableSrv}</div></div></div>
            </div>
          </div>

          <div class="rp-section">
            <div class="rp-sub-title-indicador">7.1 Enfermedades y Condiciones Prevalentes Globales (Top 7)</div>
            <table class="ind-table"><thead><tr><th>Condición / Diagnóstico (CIE-10)</th><th style="width:50pt;">N° Casos Globales</th><th>Grupo etario predominante</th></tr></thead><tbody>${filasDiagnosticos}</tbody></table>
          </div>

          <div class="rp-firma">
            <div class="rp-firma-item"><img src="/static/img/firma.webp" style="height:50px;object-fit:contain;display:block;margin:0 auto;" onerror="this.style.display='none'"/><div style="font-weight:bold;">Cristian F. Calentura V.</div><div>Auditoría / Análisis de Datos</div></div>
            <div class="rp-firma-item"><div style="font-weight:bold;">___________________________</div><div>Coordinación General APS</div></div>
          </div>
          <div class="rp-pie-page">Empresa Social del Estado — Villavicencio · Sistema INFORMES ESE · Generado el ${hoy} · Resolución 763/2025</div>
        `;

        document.getElementById('seccionImprimible').innerHTML = html;
        document.getElementById('loadingOverlay').style.display = 'none';

        // Ejecutamos print asegurándonos que el DOM ya cargó los base64
        setTimeout(() => { window.print(); }, 300);

    }, 500); // 500ms para asegurar que los gráficos canvas están completamente dibujados antes de convertirlos a imagen
}

// Iniciar al cargar
document.addEventListener('DOMContentLoaded', loadDashboard);
