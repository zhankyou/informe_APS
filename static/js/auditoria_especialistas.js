const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:5001' : window.location.origin;
const token = localStorage.getItem('informes_token');
if (!token) window.location.href = '/login';

function fmt(n) { return Number(n || 0).toLocaleString('es-CO'); }
const setVal = (id, v) => { const el = document.getElementById(id); if(el) { el.textContent = fmt(v); el.classList.remove('loading'); }};
const setValInput = (id, v) => { const el = document.getElementById(id); if(el) el.value = v; };

let todosLosCorreos = [];
let todosLosNombres = [];

async function cargarFiltros() {
    try {
        const resp1 = await fetch(`${API_BASE}/api/encuestadores`, { headers:{ 'Authorization':'Bearer '+token } });
        if (resp1.ok) {
            const data1 = await resp1.json();
            todosLosCorreos = data1.map(item => item.correo || item.usuario || item).filter(Boolean);
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

        if (!val) {
            dropdown.style.display = 'none';
            return;
        }

        // Filtrar coincidencias y limitar a los 10 primeros resultados para no saturar el DOM
        const filtrados = [...new Set(dataArray)].filter(x => x.toLowerCase().includes(val)).slice(0, 10);

        if (filtrados.length > 0) {
            filtrados.forEach(item => {
                const div = document.createElement('div');
                div.className = 'custom-dropdown-item';
                div.textContent = item;

                // Mousedown se dispara antes del blur del input
                div.onmousedown = function(e) {
                    e.preventDefault();
                    input.value = item;
                    dropdown.style.display = 'none';

                    // Limpiar el filtro opuesto para evitar consultas cruzadas nulas
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

    input.addEventListener('focus', function() {
        if (this.value.trim()) this.dispatchEvent(new Event('input'));
    });

    input.addEventListener('blur', function() {
        // Un pequeño retraso asegura que el dropdown se cierre suavemente si se clickea afuera
        setTimeout(() => dropdown.style.display = 'none', 150);
    });
}

cargarFiltros();

function copiarTexto(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.value)
      .then(() => alert('¡Texto copiado al portapapeles!'))
      .catch(err => alert('Fallo en el copiado: ' + err));
}

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
        setVal('a-des-tot', data.desistimientos?.total);
        setVal('a-des-err', data.desistimientos?.con_error);
        setVal('a-pcc-pla', data.pcc?.planes);
        setVal('a-pcc-int', data.pcc?.integrantes);
        setVal('a-pcc-err', data.pcc?.con_error);
        setValInput('txtPccDetalles', data.pcc?.reporte_detalles);

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
                tbodyFisio.innerHTML += `<tr>
                    <td>${r.id}</td><td>${r.especialista_email}</td><td>${r.fecha_visita}</td><td>${r.territorio}</td>
                    <td>${r.microterritorio}</td><td>${r.codigo_familia}</td><td>${r.municipio}</td><td>${r.barrio}</td>
                    <td>${r.direccion}</td><td>${r.latitud}</td><td>${r.longitud}</td><td>${r.nombre_fisioterapeuta}</td>
                    <td>${r.registro_profesional}</td><td>${r.nombre_jefe_hogar}</td><td>${r.doc_identidad}</td>
                    <td>${r.telefono_contacto}</td><td>${r.total_integrantes}</td><td>${r.familia_visita_no}</td>
                    <td>${r.tamizaje_motor}</td><td>${r.riesgo_caidas}</td><td>${r.barreras_arquitectonicas}</td>
                    <td>${r.riesgo_ergonomico}</td><td>${r.acciones_educacion}</td><td>${r.canalizacion}</td>
                    <td>${r.sintesis_evidencias}</td><td>${r.evidencias_drive_urls}</td><td>${r.firma_profesional}</td>
                    <td>${r.cc_profesional}</td><td>${r.firma_jefe}</td><td>${r.cc_jefe}</td><td>${r.created_at}</td>
                    <td>${r.synced_at}</td><td>${r.is_deleted}</td><td>${r.nombre_fisio}</td><td>${r.evaluacion}</td>
                    <td>${r.plan_cuidado}</td><td>${r.remite}</td><td>${r.cc_cuidador}</td><td>${r.firma_cuidador}</td>
                    <td>${r.seguimiento}</td><td>${r.sintesis_analisis}</td><td>${r.metas}</td>
                </tr>`;
            });
        } else {
            tbodyFisio.innerHTML = '<tr><td colspan="42" style="text-align:center; padding:1.5rem;">Sin registros en Fisioterapia.</td></tr>';
        }

        const tbodyNutri = document.querySelector('#tablaNutricion tbody');
        tbodyNutri.innerHTML = '';
        if(data.formularios_especialistas?.tabla_nutricionista && data.formularios_especialistas.tabla_nutricionista.length > 0) {
            data.formularios_especialistas.tabla_nutricionista.forEach(r => {
                tbodyNutri.innerHTML += `<tr>
                    <td>${r.id}</td><td>${r.especialista_email}</td><td>${r.fecha_visita}</td><td>${r.territorio}</td>
                    <td>${r.microterritorio}</td><td>${r.codigo_familia}</td><td>${r.municipio}</td><td>${r.barrio}</td>
                    <td>${r.direccion}</td><td>${r.latitud}</td><td>${r.longitud}</td><td>${r.nombre_nutricionista}</td>
                    <td>${r.registro_profesional}</td><td>${r.nombre_jefe_hogar}</td><td>${r.doc_identidad}</td>
                    <td>${r.telefono_contacto}</td><td>${r.total_integrantes}</td><td>${r.familia_visita_no}</td>
                    <td>${r.no_familia}</td><td>${r.antropometria}</td><td>${r.seguridad_alimentaria}</td>
                    <td>${r.plan_cuidado}</td><td>${r.seguimiento}</td><td>${r.remite}</td><td>${r.evidencias_drive_urls}</td>
                    <td>${r.firma_profesional}</td><td>${r.cc_profesional}</td><td>${r.firma_cuidador}</td>
                    <td>${r.cc_cuidador}</td><td>${r.created_at}</td><td>${r.synced_at}</td><td>${r.is_deleted}</td>
                    <td>${r.acc_disp}</td><td>${r.consumo}</td><td>${r.hfias}</td><td>${r.lineas_accion}</td>
                    <td>${r.lineas_otra}</td><td>${r.compromiso}</td>
                </tr>`;
            });
        } else {
            tbodyNutri.innerHTML = '<tr><td colspan="38" style="text-align:center; padding:1.5rem;">Sin registros en Nutrición.</td></tr>';
        }

        const tbodyResp = document.querySelector('#tablaRespiratoria tbody');
        tbodyResp.innerHTML = '';
        if(data.formularios_especialistas?.tabla_respiratoria && data.formularios_especialistas.tabla_respiratoria.length > 0) {
            data.formularios_especialistas.tabla_respiratoria.forEach(r => {
                tbodyResp.innerHTML += `<tr>
                    <td>${r.id}</td><td>${r.especialista_email}</td><td>${r.fecha_visita}</td><td>${r.territorio}</td>
                    <td>${r.microterritorio}</td><td>${r.codigo_familia}</td><td>${r.municipio}</td><td>${r.barrio}</td>
                    <td>${r.direccion}</td><td>${r.latitud}</td><td>${r.longitud}</td><td>${r.nombre_profesional}</td>
                    <td>${r.registro_profesional}</td><td>${r.nombre_jefe_hogar}</td><td>${r.doc_identidad}</td>
                    <td>${r.telefono_contacto}</td><td>${r.total_integrantes}</td><td>${r.familia_visita_no}</td>
                    <td>${r.no_familia}</td><td>${r.composicion_familiar}</td><td>${r.riesgos_intradomiciliarios}</td>
                    <td>${r.acciones_educacion}</td><td>${r.seguimiento_era}</td><td>${r.evidencias_drive_urls}</td>
                    <td>${r.firma_profesional}</td><td>${r.cc_profesional}</td><td>${r.firma_cuidador}</td>
                    <td>${r.cc_cuidador}</td><td>${r.created_at}</td><td>${r.synced_at}</td><td>${r.is_deleted}</td>
                    <td>${r.sintomatologia}</td><td>${r.plan_cuidado}</td><td>${r.remite}</td><td>${r.seguimiento}</td>
                </tr>`;
            });
        } else {
            tbodyResp.innerHTML = '<tr><td colspan="35" style="text-align:center; padding:1.5rem;">Sin registros en Terapia Respiratoria.</td></tr>';
        }

        setVal('a-pcf-fam', data.pcf?.familias_intervenidas);
        setVal('a-pcf-fam-dup', data.pcf?.familias_duplicadas);
        setVal('a-pcf-int', data.pcf?.integrantes_intervenidos);
        setVal('a-pcf-int-dup', data.pcf?.integrantes_duplicados);
        setValInput('txtPcfErrores', data.pcf?.reporte_errores);

        const tbodyPcfPrin = document.querySelector('#tablaExcelPcfPrincipal tbody');
        tbodyPcfPrin.innerHTML = '';
        if(data.pcf?.tabla_principal && data.pcf.tabla_principal.length > 0) {
            data.pcf.tabla_principal.forEach(r => {
                tbodyPcfPrin.innerHTML += `<tr>
                    <td>${r.ec5_uuid}</td><td>${r.created_at}</td><td>${r.uploaded_at}</td><td>${r.created_by}</td>
                    <td>${r.lat_1_1_geolocalizacin}</td><td>${r.long_1_1_geolocalizacin}</td><td>${r['4_3_perfil_profesion']}</td>
                    <td>${r['5_4_nombre_del_profe']}</td><td>${r['9_7_territorio']}</td><td>${r['10_8_microterritorio']}</td>
                    <td>${r['11_9_identificacin_d']}</td><td>${r['12_91_identificacin_']}</td><td>${r['13_10_identificacin_']}</td>
                    <td>${r['14_101_identificacin']}</td><td>${r['29_integrantes_inter']}</td><td>${r['73_17_realizara_la_e']}</td>
                    <td>${r['98_resumen_de_interv']}</td>
                </tr>`;
            });
        } else {
            tbodyPcfPrin.innerHTML = '<tr><td colspan="17" style="text-align:center; padding:1.5rem;">Sin registros en Planes de Cuidado Familiar.</td></tr>';
        }

        const tbodyPcfInt = document.querySelector('#tablaExcelPcfIntegrantes tbody');
        tbodyPcfInt.innerHTML = '';
        if(data.pcf?.tabla_integrantes && data.pcf.tabla_integrantes.length > 0) {
            data.pcf.tabla_integrantes.forEach(r => {
                tbodyPcfInt.innerHTML += `<tr>
                    <td>${r.ec5_branch_owner_uuid}</td><td>${r.ec5_branch_uuid}</td><td>${r.created_at}</td>
                    <td>${r.uploaded_at}</td><td>${r.created_by}</td><td>${r.title}</td><td>${r['31_1_primer_nombre']}</td>
                    <td>${r['33_3_primer_apellido']}</td><td>${r['35_5_tipo_de_documen']}</td><td>${r['36_6_numero_de_docum']}</td>
                    <td>${r['38_8_fecha_de_nacimi']}</td><td>${r['41_11_sexo']}</td><td>${r['46_16_numero_de_celu']}</td>
                    <td>${r['57_23_que_tipo_de_co']}</td><td>${r['67_237_tema_central_']}</td><td>${r['69_239_metodologa_ed']}</td>
                    <td>${r['71_2311_ruta_sugerid']}</td><td>${r['72_24_resumen_de_val']}</td>
                </tr>`;
            });
        } else {
            tbodyPcfInt.innerHTML = '<tr><td colspan="18" style="text-align:center; padding:1.5rem;">Sin registros en Planes de Cuidado Individual.</td></tr>';
        }

        document.getElementById('resultadosAuditoria').style.display = 'block';

    } catch(err) {
        alert(`Error: ${err.message}`);
        document.getElementById('emptyState').style.display = 'block';
    } finally {
        document.getElementById('loadingOverlay').style.display = 'none';
    }
}
