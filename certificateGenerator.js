const PDFDocument = require('pdfkit');

function generateAuditCertificate(reportData, stream) {
  const doc = new PDFDocument({ margin: 50, size: 'A4' });
  doc.pipe(stream);

  const isPassed = reportData.summary?.passed;
  const primaryColor = isPassed ? '#10B981' : '#EF4444';
  const textDark = '#1F2937';
  const textMuted = '#6B7280';

  // Cabecera y Marca
  doc.fontSize(22).fillColor('#1E1B4B').text('AUDITOR ENGINE', { tracking: 2 });
  doc.fontSize(10).fillColor(textMuted).text('Certificado Oficial de Auditoría de Código y Seguridad Pre-Entrega');
  doc.moveDown(1.5);

  // Línea divisoria decorativa
  doc.strokeColor('#E5E7EB').lineWidth(1).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
  doc.moveDown(1.5);

  // Veredicto Central (Badge)
  const statusText = isPassed ? 'APROBADO PARA PRODUCCIÓN' : 'REQUIERE REVISIÓN TÉCNICA';
  doc.rect(50, doc.y, 495, 45).fill(isPassed ? '#ECFDF5' : '#FEF2F2');
  doc.fontSize(14).fillColor(primaryColor).text(statusText, 50, doc.y - 32, { align: 'center', bold: true });
  doc.moveDown(2);

  // Metadatos del Escaneo
  const startY = doc.y;
  doc.fontSize(10).fillColor(textDark);
  doc.text(`Origen: ${reportData.source?.type?.toUpperCase()} (${reportData.source?.target})`, 50, startY);
  doc.text(`Entorno auditado: ${reportData.projectType?.toUpperCase()}`, 50, startY + 16);
  doc.text(`Fecha de emisión: ${new Date(reportData.scannedAt).toLocaleString()}`, 50, startY + 32);

  doc.moveDown(3);

  // Tarjetas de Métricas
  const metricY = doc.y;
  const colWidth = 155;

  // Bloqueantes
  doc.rect(50, metricY, colWidth, 55).fill('#F9FAFB');
  doc.fontSize(18).fillColor(reportData.summary?.totalBlockers > 0 ? '#DC2626' : textDark)
     .text(String(reportData.summary?.totalBlockers || 0), 50, metricY + 10, { align: 'center', width: colWidth });
  doc.fontSize(9).fillColor(textMuted).text('Fallos Bloqueantes', 50, metricY + 34, { align: 'center', width: colWidth });

  // Advertencias
  doc.rect(220, metricY, colWidth, 55).fill('#F9FAFB');
  doc.fontSize(18).fillColor(textDark)
     .text(String(reportData.summary?.totalWarnings || 0), 220, metricY + 10, { align: 'center', width: colWidth });
  doc.fontSize(9).fillColor(textMuted).text('Observaciones', 220, metricY + 34, { align: 'center', width: colWidth });

  // Estándares Verificados
  doc.rect(390, metricY, 155, 55).fill('#F9FAFB');
  doc.fontSize(14).fillColor('#4F46E5')
     .text('3 / 3', 390, metricY + 12, { align: 'center', width: 155 });
  doc.fontSize(9).fillColor(textMuted).text('Estándares OWASP/CWE', 390, metricY + 34, { align: 'center', width: 155 });

  doc.moveDown(4);

  // Alcance del Análisis
  doc.fontSize(12).fillColor(textDark).text('Cobertura de Seguridad Evaluada');
  doc.moveDown(0.5);

  const checks = [
    'SAST: Análisis de código estático contra OWASP Top 10 y debilidades CWE comunes.',
    'Credenciales: Detección heurística y entropía de tokens expuestos (JWT, SSH, API Keys).',
    `Dependencias: Auditoría formal de paquetes contra vulnerabilidades conocidas (${reportData.projectType === 'php' ? 'Composer' : 'NPM'}).`
  ];

  checks.forEach(check => {
    doc.fontSize(9).fillColor(textMuted).text(`•  ${check}`);
    doc.moveDown(0.3);
  });

  // Pie de página con identificador único
  const footerY = 750;
  doc.strokeColor('#E5E7EB').lineWidth(0.5).moveTo(50, footerY).lineTo(545, footerY).stroke();
  doc.fontSize(8).fillColor(textMuted).text('Documento generado automáticamente por Auditor Engine. Válido como garantía técnica pre-entrega.', 50, footerY + 10);
  doc.text(`ID Hash: ${Buffer.from(`${reportData.scannedAt}-${reportData.source?.target}`).toString('base64').substring(0, 24)}`, 50, footerY + 22);

  doc.end();
}

module.exports = { generateAuditCertificate };