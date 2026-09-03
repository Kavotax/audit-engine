const fs = require('fs');
const path = require('path');

function generateHtmlReport(data, projectName = 'Proyecto Auditado') {
  const isPassed = data.summary.passed;
  const statusBadge = data.summary.statusBadge || (isPassed ? 'APROBADO' : 'REQUIERE REVISIÓN');
  
  let statusColor = '#10B981'; // Verde
  if (!isPassed) {
    statusColor = '#EF4444'; // Rojo
  } else if (data.summary.totalWarnings > 0) {
    statusColor = '#F59E0B'; // Ámbar / Amarillo
  }

  const renderTableRows = (items, bgBadge, textBadge) => items.map(item => `
    <tr style="border-bottom: 1px solid #F3F4F6;">
      <td style="padding: 10px; font-family: monospace; font-size: 13px; color: #1F2937; width: 25%;">${item.path}:${item.startLine || '1'}</td>
      <td style="padding: 10px; font-size: 13px; color: #4B5563; line-height: 1.4;">${item.message}</td>
      <td style="padding: 10px; text-align: right; width: 15%;">
        <span style="background: ${bgBadge}; color: ${textBadge}; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">
          ${item.severity}
        </span>
      </td>
    </tr>
  `).join('');

  const blockersRows = renderTableRows(data.sast.blockers || [], '#FEE2E2', '#991B1B');
  const warningsRows = renderTableRows(data.sast.warnings || [], '#FEF3C7', '#92400E');

  return `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Certificado de Calidad y Entrega - ${projectName}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F9FAFB; color: #111827; padding: 40px; margin: 0; }
    .card { max-width: 850px; margin: auto; background: white; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); border: 1px solid #E5E7EB; }
    .header { border-bottom: 2px solid #F3F4F6; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
    .badge { background: ${statusColor}15; color: ${statusColor}; border: 1px solid ${statusColor}; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 13px; text-transform: uppercase; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 24px 0; }
    .metric { background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; padding: 14px; text-align: center; }
    .metric-value { font-size: 22px; font-weight: bold; margin-top: 4px; }
    .section-title { font-size: 15px; font-weight: 600; margin-top: 24px; margin-bottom: 10px; border-bottom: 1px solid #E5E7EB; padding-bottom: 6px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; text-align: left; }
    th { background: #F9FAFB; padding: 8px 10px; font-size: 12px; font-weight: 600; color: #6B7280; text-transform: uppercase; border-bottom: 1px solid #E5E7EB; }
    .footer { margin-top: 32px; font-size: 12px; color: #6B7280; text-align: center; border-top: 1px solid #F3F4F6; padding-top: 16px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div>
        <h1 style="margin: 0; font-size: 22px;">Certificado de Auditoría Pre-Entrega</h1>
        <p style="margin: 4px 0 0 0; color: #6B7280; font-size: 14px;">
          Proyecto: <strong>${projectName}</strong> | Entorno: <code>${data.projectType}</code> | Fecha: ${new Date(data.scannedAt).toLocaleDateString()}
        </p>
      </div>
      <span class="badge">${statusBadge}</span>
    </div>

    <div class="grid">
      <div class="metric">
        <div style="font-size: 12px; color: #6B7280;">Fallos Bloqueantes</div>
        <div class="metric-value" style="color: ${data.summary.totalBlockers > 0 ? '#EF4444' : '#10B981'}">
          ${data.summary.totalBlockers}
        </div>
      </div>
      <div class="metric">
        <div style="font-size: 12px; color: #6B7280;">Observaciones / Advertencias</div>
        <div class="metric-value" style="color: ${data.summary.totalWarnings > 0 ? '#F59E0B' : '#10B981'}">
          ${data.summary.totalWarnings}
        </div>
      </div>
      <div class="metric">
        <div style="font-size: 12px; color: #6B7280;">Licencias Incompatibles</div>
        <div class="metric-value" style="color: ${data.licenses.hasRestrictedLicenses ? '#EF4444' : '#10B981'}">
          ${data.licenses.hasRestrictedLicenses ? 'Detectadas' : '0'}
        </div>
      </div>
    </div>

    ${data.sast.blockers && data.sast.blockers.length > 0 ? `
      <div class="section-title" style="color: #DC2626;">🚨 Hallazgos Bloqueantes (Requieren corrección antes de entrega)</div>
      <table>
        <thead>
          <tr>
            <th>Ubicación</th>
            <th>Descripción</th>
            <th style="text-align: right;">Severidad</th>
          </tr>
        </thead>
        <tbody>
          ${blockersRows}
        </tbody>
      </table>
    ` : ''}

    ${data.sast.warnings && data.sast.warnings.length > 0 ? `
      <div class="section-title" style="color: #D97706;">⚠️ Recomendaciones y Buenas Prácticas (No bloqueantes)</div>
      <table>
        <thead>
          <tr>
            <th>Ubicación</th>
            <th>Descripción</th>
            <th style="text-align: right;">Severidad</th>
          </tr>
        </thead>
        <tbody>
          ${warningsRows}
        </tbody>
      </table>
    ` : ''}

    <div class="section-title">Compatibilidad de Licencias</div>
    <p style="font-size: 13px; color: #374151; margin: 4px 0;">
      Paquetes externos analizados: <strong>${data.licenses.totalFound}</strong> | 
      Licencias: ${data.licenses.allLicenses.join(', ') || 'Sin librerías externas registradas'}
    </p>

    <div class="footer">
      Este reporte certifica el estado del repositorio mediante análisis estático y verificación de dependencias a la fecha de emisión. Las advertencias listadas corresponden a sugerencias de hardening o buenas prácticas recomendadas.
    </div>
  </div>
</body>
</html>
  `;
}

const reportRaw = fs.readFileSync(path.join(__dirname, 'scan-report.json'), 'utf8');
const reportData = JSON.parse(reportRaw);
const html = generateHtmlReport(reportData, 'RayoVerde');

fs.writeFileSync(path.join(__dirname, 'Certificado-Entrega.html'), html);
console.log('✅ Certificado HTML actualizado en: Certificado-Entrega.html');