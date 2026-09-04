const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:5001' : window.location.origin;
const token = localStorage.getItem('informes_token');

function logout() {
    localStorage.removeItem('informes_token');
    window.location.href = '/login';
}

if (!token) {
    window.location.href = '/login';
} else {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        const payload = JSON.parse(jsonPayload);
        document.getElementById('sidebarNombre').textContent = payload.nombre || payload.sub || 'Usuario Registrado';
        document.getElementById('sidebarRol').textContent = payload.rol || 'ESPECIALISTA';
    } catch(e) {
        document.getElementById('sidebarNombre').textContent = 'Usuario Registrado';
        document.getElementById('sidebarRol').textContent = 'SESIÓN ACTIVA';
    }
}

function fmt(n) { return Number(n || 0).toLocaleString('es-CO'); }
const setVal = (id, v) => { const el = document.getElementById(id); if(el) { el.textContent = fmt(v); el.classList.remove('loading'); }};
const setValInput = (id, v) => { const el = document.getElementById(id); if(el) el.value = v; };

let todosLosCorreos = [];
let todosLosNombres = [];
let mapPcfInstance = null;
let mapEspInstance = null;

async function cargarFiltros() {
    try {
        const resp1 = await fetch(`${API_BASE}/api/encuestadores`, { headers:{ 'Authorization':'Bearer '+token } });
        if (resp1.ok) {
            const data1 = await resp1.json();
            todosLosCorreos = data1.map(item => item.correo || item.usuario || item.email || item).filter(Boolean);
        }

        const resp2 = await fetch(`${API_BASE}/api/nombres_profesionales`, { headers:{ 'Authorization':'Bearer '+token } });
        if (resp2.ok) {
            const data2 = await resp2.json();
            todosLosNombres = data2.map(item => item.nombre || item.profesional || item).filter(Boolean);
        }

        configurarAutocompletado('inputUser', 'customDropdown', todosLosCorreos);
        configurarAutocompletado('inputName', 'customDropdownName', todosLosNombres);
    } catch(e) {
        console.error("Error cargando catálogos de filtros:", e);
    }
}

function configurarAutocompletado(inputId, dropdownId, dataArray) {
    const input = document.getElementById(inputId);
    const dropdown = document.getElementById(dropdownId);
    if (!input || !dropdown) return;

    input.addEventListener('input', function() {
        const val = this.value.trim().toLowerCase();
        dropdown.innerHTML = '';

        let filtrados = [];
        if (!val) {
            filtrados = [...new Set(dataArray)].slice(0, 30);
        } else {
            filtrados = [...new Set(dataArray)].filter(x => x && x.toLowerCase().includes(val)).slice(0, 30);
        }

        if (filtrados.length > 0) {
            filtrados.forEach(item => {
                const div = document.createElement('div');
                div.className = 'custom-dropdown-item';
                div.textContent = item;

                div.onmousedown = function(e) {
                    e.preventDefault();
                    input.value = item;
                    dropdown.style.display = 'none';
                    if (inputId === 'inputUser') document.getElementById('inputName').value = '';
                    if (inputId === 'inputName') document.getElementById('inputUser').value = '';
                };
                dropdown.appendChild(div);
            });
            dropdown.style.display = 'block';
        } else {
            dropdown.style.display = 'none';
        }
    });

    input.addEventListener('focus', function() { this.dispatchEvent(new Event('input')); });
    input.addEventListener('blur', function() { setTimeout(() => dropdown.style.display = 'none', 150); });
}

cargarFiltros();

function copiarTexto(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.value)
      .then(() => alert('¡Texto copiado al portapapeles!'))
      .catch(err => alert('Fallo en el copiado: ' + err));
}

function renderizarCabeceras(targetId, columnas, tableId) {
    const head = document.getElementById(targetId);
    if(!head) return;
    let html = '';
    columnas.forEach((col, idx) => {
        html += `
            <th>
                <div class="th-wrapper">
                    <span class="th-title">${col}</span>
                    <input type="text" class="col-search-input" data-col="${idx}" placeholder="Buscar..." oninput="filtrarTablaExcel('${tableId}')">
                </div>
            </th>
        `;
    });
    head.innerHTML = html;
}

const colFisio = ['id','especialista_email','fecha_visita','territorio','microterritorio','codigo_familia','municipio','barrio','direccion','latitud','longitud','nombre_fisioterapeuta','registro_profesional','nombre_jefe_hogar','doc_identidad','telefono_contacto','total_integrantes','familia_visita_no','tamizaje_motor','riesgo_caidas','barreras_arquitectonicas','riesgo_ergonomico','acciones_educacion','canalizacion','sintesis_evidencias','evidencias_drive_urls','firma_profesional','cc_profesional','firma_jefe','cc_jefe','created_at','synced_at','is_deleted','nombre_fisio','evaluacion','plan_cuidado','remite','cc_cuidador','firma_cuidador','seguimiento','sintesis_analisis','metas'];
const colNutri = ['id','especialista_email','fecha_visita','territorio','microterritorio','codigo_familia','municipio','barrio','direccion','latitud','longitud','nombre_nutricionista','registro_profesional','nombre_jefe_hogar','doc_identidad','telefono_contacto','total_integrantes','familia_visita_no','no_familia','antropometria','seguridad_alimentaria','plan_cuidado','seguimiento','remite','evidencias_drive_urls','firma_profesional','cc_profesional','firma_cuidador','cc_cuidador','created_at','synced_at','is_deleted','acc_disp','consumo','hfias','lineas_accion','lineas_otra','compromiso'];
const colResp = ['id','especialista_email','fecha_visita','territorio','microterritorio','codigo_familia','municipio','barrio','direccion','latitud','longitud','nombre_profesional','registro_profesional','nombre_jefe_hogar','doc_identidad','telefono_contacto','total_integrantes','familia_visita_no','no_familia','composicion_familiar','riesgos_intradomiciliarios','acciones_educacion','seguimiento_era','evidencias_drive_urls','firma_profesional','cc_profesional','firma_cuidador','cc_cuidador','created_at','synced_at','is_deleted','sintomatologia','plan_cuidado','remite','seguimiento'];
const colPcfPrin = ['ec5_uuid','created_at','uploaded_at','created_by','lat_1_1','long_1_1','perfil_profesion','nombre_del_profe','territorio','microterritorio','identificacin_d','id_91','id_10','id_101','integ_inter','realizara_e','resumen_interv'];
const colPcfInt = ['owner_uuid','branch_uuid','created_at','uploaded_at','created_by','title','primer_nombre','primer_apellido','tipo_doc','num_doc','fecha_nacimi','sexo','num_celu','tipo_de_co','tema_central','metodologia_ed','ruta_sugerida','resumen_val'];

renderizarCabeceras('headFisio', colFisio, 'tablaFisioterapia');
renderizarCabeceras('headNutri', colNutri, 'tablaNutricion');
renderizarCabeceras('headResp', colResp, 'tablaRespiratoria');
renderizarCabeceras('headPcfPrin', colPcfPrin, 'tablaExcelPcfPrincipal');
renderizarCabeceras('headPcfInt', colPcfInt, 'tablaExcelPcfIntegrantes');

function filtrarTablaExcel(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const inputs = table.querySelectorAll('thead .col-search-input');
    const tbody = table.querySelector('tbody');
    const rows = tbody.getElementsByTagName('tr');

    for (let i = 0; i < rows.length; i++) {
        let showRow = true;
        const cells = rows[i].getElementsByTagName('td');

        if (cells.length === 1 && cells[0].colSpan > 1) continue;

        inputs.forEach(input => {
            const filterValue = input.value.trim().toLowerCase();
            const colIndex = parseInt(input.getAttribute('data-col'));

            if (filterValue !== "") {
                const cellText = cells[colIndex] ? cells[colIndex].textContent.toLowerCase() : "";
                if (cellText.indexOf(filterValue) === -1) {
                    showRow = false;
                }
            }
        });

        rows[i].style.display = showRow ? "" : "none";
    }
}

function renderizarMapas(dataMapas) {
    if (!mapPcfInstance) {
        mapPcfInstance = L.map('mapaPcf').setView([4.11963, -73.564361], 8);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(mapPcfInstance);
    } else {
        mapPcfInstance.eachLayer(layer => { if(layer instanceof L.Marker) mapPcfInstance.removeLayer(layer); });
    }

    if (!mapEspInstance) {
        mapEspInstance = L.map('mapaEsp').setView([4.11963, -73.564361], 8);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(mapEspInstance);
    } else {
        mapEspInstance.eachLayer(layer => { if(layer instanceof L.Marker) mapEspInstance.removeLayer(layer); });
    }

    setTimeout(() => {
        mapPcfInstance.invalidateSize();
        mapEspInstance.invalidateSize();
    }, 400);

    let boundsPcf = L.latLngBounds();
    let boundsEsp = L.latLngBounds();
    let countPcf = 0, countEsp = 0;

    if (dataMapas.pcf_puntos && dataMapas.pcf_puntos.length > 0) {
        dataMapas.pcf_puntos.forEach(pt => {
            L.marker([pt.lat, pt.lon]).bindPopup(pt.popup).addTo(mapPcfInstance);
            boundsPcf.extend([pt.lat, pt.lon]);
            countPcf++;
        });
        if(countPcf > 0) mapPcfInstance.fitBounds(boundsPcf, { padding: [20, 20] });
    }

    if (dataMapas.esp_puntos && dataMapas.esp_puntos.length > 0) {
        dataMapas.esp_puntos.forEach(pt => {
            L.marker([pt.lat, pt.lon]).bindPopup(pt.popup).addTo(mapEspInstance);
            boundsEsp.extend([pt.lat, pt.lon]);
            countEsp++;
        });
        if(countEsp > 0) mapEspInstance.fitBounds(boundsEsp, { padding: [20, 20] });
    }

    setValInput('txtMapasErrores', dataMapas.errores.join('\n') || "✅ Todas las atenciones cuentan con coordenadas válidas.");
}

async function buscarAuditoriaEspecialistas() {
    const email = document.getElementById('inputUser').value.trim();
    const nombre = document.getElementById('inputName').value.trim();
    const fi = document.getElementById('inputInicio').value;
    const ff = document.getElementById('inputFin').value;

    if ((!email && !nombre) || !fi || !ff) {
        alert('Ingrese correo o nombre, y el rango de fechas completo.');
        return;
    }

    document.getElementById('loadingOverlay').style.display = 'flex';
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('resultadosAuditoria').style.display = 'none';

    document.querySelectorAll('.col-search-input').forEach(input => input.value = '');

    try {
        let urlParam = email ? `usuario=${encodeURIComponent(email)}` : `nombre=${encodeURIComponent(nombre)}`;
        const resp = await fetch(`${API_BASE}/api/auditoria_especialistas?${urlParam}&fecha_inicio=${fi}&fecha_fin=${ff}`, {
            headers:{ 'Authorization':'Bearer '+token }
        });

        if (resp.status === 401) return window.location.href = '/login';
        const data = await resp.json();
        if (data.error) throw new Error(data.error);

        setValInput('textoErroresGlobal', data.reporte_errores_texto);

        setVal('nov-ok', data.novedades?.correctos);
        setVal('nov-no-caract', data.novedades?.sin_caracterizacion);
        setVal('nov-no-pcf', data.novedades?.sin_pcf);
        setVal('nov-no-pci', data.novedades?.sin_pci);
        setVal('nov-tot', data.novedades?.total_evaluados);

        const tbodyNov = document.querySelector('#tablaNovedades tbody');
        tbodyNov.innerHTML = '';
        if(!data.novedades?.detalle || data.novedades.detalle.length === 0) {
            tbodyNov.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem;">Sin novedades detectadas</td></tr>';
        } else {
            data.novedades.detalle.forEach(nov => {
                let color = nov.tipo.includes('Sin') ? 'var(--red)' : 'var(--orange)';
                tbodyNov.innerHTML += `
                    <tr>
                        <td style="font-family:monospace; font-size:0.85rem;">${nov.fecha}</td>
                        <td style="font-weight:600;">${nov.paciente}</td>
                        <td style="color:var(--muted);">${nov.tabla_origen}</td>
                        <td style="color:var(--navy); font-weight:600;">${nov.tipo}</td>
                        <td style="color:${color}; font-weight:500;">${nov.detalle}</td>
                    </tr>
                `;
            });
        }

        setVal('a-esp-fam', data.formularios_especialistas?.familias_intervenidas);
        setVal('a-esp-dup', data.formularios_especialistas?.duplicados);
        setVal('a-esp-err', data.formularios_especialistas?.errores);

        const tbodyFisio = document.querySelector('#tablaFisioterapia tbody');
        tbodyFisio.innerHTML = '';
        if(data.formularios_especialistas?.tabla_fisioterapia && data.formularios_especialistas.tabla_fisioterapia.length > 0) {
            data.formularios_especialistas.tabla_fisioterapia.forEach(r => {
                tbodyFisio.innerHTML += `<tr>${colFisio.map(c => `<td>${r[c]}</td>`).join('')}</tr>`;
            });
        } else { tbodyFisio.innerHTML = `<tr><td colspan="${colFisio.length}" style="text-align:center; padding:1.5rem;">Sin registros en Fisioterapia.</td></tr>`; }

        const tbodyNutri = document.querySelector('#tablaNutricion tbody');
        tbodyNutri.innerHTML = '';
        if(data.formularios_especialistas?.tabla_nutricionista && data.formularios_especialistas.tabla_nutricionista.length > 0) {
            data.formularios_especialistas.tabla_nutricionista.forEach(r => {
                tbodyNutri.innerHTML += `<tr>${colNutri.map(c => `<td>${r[c]}</td>`).join('')}</tr>`;
            });
        } else { tbodyNutri.innerHTML = `<tr><td colspan="${colNutri.length}" style="text-align:center; padding:1.5rem;">Sin registros en Nutrición.</td></tr>`; }

        const tbodyResp = document.querySelector('#tablaRespiratoria tbody');
        tbodyResp.innerHTML = '';
        if(data.formularios_especialistas?.tabla_respiratoria && data.formularios_especialistas.tabla_respiratoria.length > 0) {
            data.formularios_especialistas.tabla_respiratoria.forEach(r => {
                tbodyResp.innerHTML += `<tr>${colResp.map(c => `<td>${r[c]}</td>`).join('')}</tr>`;
            });
        } else { tbodyResp.innerHTML = `<tr><td colspan="${colResp.length}" style="text-align:center; padding:1.5rem;">Sin registros en Terapia Respiratoria.</td></tr>`; }

        setVal('a-pcf-fam', data.pcf?.familias_intervenidas);
        setVal('a-pcf-fam-dup', data.pcf?.familias_duplicadas);
        setVal('a-pcf-int', data.pcf?.integrantes_intervenidos);
        setVal('a-pcf-int-dup', data.pcf?.integrantes_duplicados);
        setValInput('txtPcfErrores', data.pcf?.reporte_errores);

        const tbodyPcfPrin = document.querySelector('#tablaExcelPcfPrincipal tbody');
        tbodyPcfPrin.innerHTML = '';
        if(data.pcf?.tabla_principal && data.pcf.tabla_principal.length > 0) {
            data.pcf.tabla_principal.forEach(r => {
                tbodyPcfPrin.innerHTML += `<tr>${colPcfPrin.map(c => `<td>${r[c]}</td>`).join('')}</tr>`;
            });
        } else { tbodyPcfPrin.innerHTML = `<tr><td colspan="${colPcfPrin.length}" style="text-align:center; padding:1.5rem;">Sin registros en Planes de Cuidado Familiar.</td></tr>`; }

        const tbodyPcfInt = document.querySelector('#tablaExcelPcfIntegrantes tbody');
        tbodyPcfInt.innerHTML = '';
        if(data.pcf?.tabla_integrantes && data.pcf.tabla_integrantes.length > 0) {
            data.pcf.tabla_integrantes.forEach(r => {
                tbodyPcfInt.innerHTML += `<tr>${colPcfInt.map(c => `<td>${r[c]}</td>`).join('')}</tr>`;
            });
        } else { tbodyPcfInt.innerHTML = `<tr><td colspan="${colPcfInt.length}" style="text-align:center; padding:1.5rem;">Sin registros en Planes de Cuidado Individual.</td></tr>`; }

        document.getElementById('resultadosAuditoria').style.display = 'block';

        if (data.mapas) {
            renderizarMapas(data.mapas);
        }

    } catch(err) {
        alert(`Error: ${err.message}`);
        document.getElementById('emptyState').style.display = 'block';
    } finally {
        document.getElementById('loadingOverlay').style.display = 'none';
    }
}
