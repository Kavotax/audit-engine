const fs = require('fs');
const path = require('path');

function generateHtmlReport(data, projectName = 'Audited Project') {
  const isPassed = data.summary.passed;
  const statusBadge = data.summary.statusBadge || (isPassed ? 'APPROVED FOR DELIVERY' : 'REQUIRES REVISION');
  
  let statusColor = '#10B981'; // Green
  if (!isPassed) {
    statusColor = '#EF4444'; // Red
  } else if (data.summary.totalWarnings > 0) {
    statusColor = '#F59E0B'; // Amber
  }

  const renderTableRows = (items, bgBadge, textBadge) => items.map(item => `
    <tr style="border-bottom: 1px solid #F3F4F6;">
      <td style="padding: 10px; font-family: monospace; font-size: 13px; color: #1F2937; width: 25%;">${item.path}:${item.startLine || '1'}</td>
      <td style="padding: 10px; font-size: 13px; color: #4B5563; line-height: 1.4;">
        ${item.message}
        ${item.fix ? `<div style="font-size: 11px; color: #6B7280; margin-top: 4px;"><strong>Fix:</strong> ${item.fix}</div>` : ''}
      </td>
      <td style="padding: 10px; text-align: right; width: 15%;">
        <span style="background: ${bgBadge}; color: ${textBadge}; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">
          ${item.severity}
        </span>
      </td>
    </tr>
  `).join('');

  // Collect blockers and warnings from SAST, secrets, and dependencies
  const blockers = [
    ...(data.sast?.blockers || []),
    ...((data.dependenciesVulnerabilities || []).filter(v => v.category === 'Blocker' || v.severity === 'CRITICAL' || v.severity === 'HIGH'))
  ];

  const warnings = [
    ...(data.sast?.warnings || []),
    ...((data.dependenciesVulnerabilities || []).filter(v => v.category === 'Warning' || (v.severity !== 'CRITICAL' && v.severity !== 'HIGH')))
  ];

  const blockersRows = renderTableRows(blockers, '#FEE2E2', '#991B1B');
  const warningsRows = renderTableRows(warnings, '#FEF3C7', '#92400E');

  const hasLicenses = Boolean(data.licenses);
  const restrictedLicenses = data.licenses?.hasRestrictedLicenses;
  const totalPackages = data.licenses?.totalFound ?? (data.summary.totalVulnerabilities !== undefined ? 'Audited' : 'N/A');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Quality & Security Delivery Certificate - ${projectName}</title>
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
        <h1 style="margin: 0; font-size: 22px;">Pre-Delivery Audit Certificate</h1>
        <p style="margin: 4px 0 0 0; color: #6B7280; font-size: 14px;">
          Project: <strong>${projectName}</strong> | Environment: <code>${data.projectType}</code> | Date: ${new Date(data.scannedAt).toLocaleDateString()}
        </p>
      </div>
      <span class="badge">${statusBadge}</span>
    </div>

    <div class="grid">
      <div class="metric">
        <div style="font-size: 12px; color: #6B7280;">Critical Blockers</div>
        <div class="metric-value" style="color: ${data.summary.totalBlockers > 0 ? '#EF4444' : '#10B981'}">
          ${data.summary.totalBlockers}
        </div>
      </div>
      <div class="metric">
        <div style="font-size: 12px; color: #6B7280;">Warnings / Observations</div>
        <div class="metric-value" style="color: ${data.summary.totalWarnings > 0 ? '#F59E0B' : '#10B981'}">
          ${data.summary.totalWarnings}
        </div>
      </div>
      <div class="metric">
        <div style="font-size: 12px; color: #6B7280;">Incompatible Licenses</div>
        <div class="metric-value" style="color: ${restrictedLicenses ? '#EF4444' : '#10B981'}">
          ${restrictedLicenses ? 'Detected' : '0'}
        </div>
      </div>
    </div>

    ${blockers.length > 0 ? `
      <div class="section-title" style="color: #DC2626;">Critical Findings (Must be resolved before delivery)</div>
      <table>
        <thead>
          <tr>
            <th>Location</th>
            <th>Description</th>
            <th style="text-align: right;">Severity</th>
          </tr>
        </thead>
        <tbody>
          ${blockersRows}
        </tbody>
      </table>
    ` : ''}

    ${warnings.length > 0 ? `
      <div class="section-title" style="color: #D97706;">Recommendations & Best Practices (Non-blocking)</div>
      <table>
        <thead>
          <tr>
            <th>Location</th>
            <th>Description</th>
            <th style="text-align: right;">Severity</th>
          </tr>
        </thead>
        <tbody>
          ${warningsRows}
        </tbody>
      </table>
    ` : ''}

    ${hasLicenses ? `
      <div class="section-title">License Compliance</div>
      <p style="font-size: 13px; color: #374151; margin: 4px 0;">
        External packages analyzed: <strong>${totalPackages}</strong> | 
        Licenses: ${data.licenses.allLicenses?.join(', ') || 'No external libraries detected'}
      </p>
    ` : ''}

    <div class="footer">
      This report validates repository compliance through local static analysis (SAST), dependency scans, and secret detection at the time of issue. Findings reflect automated checks aligned with OWASP Top 10 and CWE standards.
    </div>
  </div>
</body>
</html>
  `;
}

// Direct execution when compiling HTML report from scan-report.json
if (require.main === module) {
  const reportPath = path.join(process.cwd(), 'scan-report.json');
  if (!fs.existsSync(reportPath)) {
    console.error(`[ERROR] Report file not found at: ${reportPath}`);
    process.exit(1);
  }

  const reportRaw = fs.readFileSync(reportPath, 'utf8');
  const reportData = JSON.parse(reportRaw);
  const projectName = process.argv[2] || 'Local Project';
  const html = generateHtmlReport(reportData, projectName);

  const outputPath = path.join(process.cwd(), 'Delivery-Certificate.html');
  fs.writeFileSync(outputPath, html);
  console.log(`[SUCCESS] HTML certificate generated at: ${outputPath}`);
}

module.exports = { generateHtmlReport };