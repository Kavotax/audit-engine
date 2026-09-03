const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const AdmZip = require('adm-zip');

function runCommand(command, cwd) {
  return new Promise((resolve) => {
    exec(command, { cwd, maxBuffer: 1024 * 1024 * 15 }, (error, stdout, stderr) => {
      resolve({ stdout: stdout ? stdout.trim() : '', stderr: stderr ? stderr.trim() : '', error });
    });
  });
}

// Clonado superficial y seguro de GitHub (públicos y privados)
async function cloneGitHubRepo(repoUrl, authToken = null) {
  const tempDir = path.join(os.tmpdir(), `audit-repo-${Date.now()}`);
  console.log(`📥 Clonando repositorio remoto (${repoUrl})...`);

  let authUrl = repoUrl.trim();
  if (authToken) {
    const rawUrl = authUrl.replace(/^https?:\/\//, '');
    authUrl = `https://${authToken}@${rawUrl}`;
  }

  const cloneCmd = `git clone --depth 1 "${authUrl}" "${tempDir}"`;
  const result = await runCommand(cloneCmd, process.cwd());

  if (result.error && !fs.existsSync(tempDir)) {
    throw new Error(`Error al clonar repositorio (verifica si es privado o requiere token): ${result.stderr || result.stdout}`);
  }

  // Si tiene package.json, resolver dependencias para escaneo de licencias y npm audit
  const hasPackageJson = fs.existsSync(path.join(tempDir, 'package.json'));
  if (hasPackageJson) {
    console.log('📦 Generando lockfile/dependencias para auditoría de paquetes...');
    await runCommand('npm install --package-lock-only', tempDir);
  }

  return tempDir;
}

// Descompresión de archivos .zip en carpeta temporal
function extractZipArchive(zipFilePath) {
  const tempDir = path.join(os.tmpdir(), `audit-zip-${Date.now()}`);
  console.log(`📦 Descomprimiendo archivo ZIP (${zipFilePath})...`);

  if (!fs.existsSync(zipFilePath)) {
    throw new Error(`El archivo .zip "${zipFilePath}" no existe.`);
  }

  const zip = new AdmZip(zipFilePath);
  zip.extractAllTo(tempDir, true);

  return tempDir;
}

// Limpieza automática de directorios temporales
function cleanupTempDir(dirPath) {
  try {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
      console.log('🧹 Directorio temporal limpiado con éxito.');
    }
  } catch (err) {
    console.warn(`⚠️ No se pudo eliminar la carpeta temporal: ${err.message}`);
  }
}

/**
 * Determina si una cadena parece un secreto criptográfico real o solo un texto de prueba / configuración
 */
function isLikelyRealSecret(str) {
  const clean = str.replace(/["'`]/g, '').trim();

  // 1. Descartar palabras compuestas simples (ej. "configured-token", "my-test-secret")
  // Si solo tiene letras minúsculas y guiones/guiones bajos sin ningún número ni mayúscula, es un placeholder
  if (/^[a-z_\-]+$/.test(clean)) {
    return false;
  }

  // 2. Descartar si son palabras legibles obvias
  if (/^(configured|test|dummy|mock|example|sample|placeholder|default)[-_]/i.test(clean)) {
    return false;
  }

  // 3. Cálculo de Entropía de Shannon básica
  // Las API Keys reales suelen tener una entropía > 3.0
  const len = clean.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = clean[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  // Tokens reales de más de 16 caracteres tienen entropía alta y variedad de caracteres
  const hasMixedTypes = (/[0-9]/.test(clean) && /[a-zA-Z]/.test(clean)) || (/[A-Z]/.test(clean) && /[a-z]/.test(clean));
  
  return entropy >= 2.8 && hasMixedTypes;
}

function scanCodeForSecrets(targetPath) {
  const ignoredProperties = [
    'primarykey',
    'foreignkey',
    'foreign_key',
    'routekey',
    'uniquekey',
    'cachekey',
    'keytype',
    'key_name'
  ];

  const secretPatterns = [
    {
      name: 'API Key / Token asignado',
      // Exige asignación a un string literal entre comillas con mínimo 16 caracteres
      regex: /(?:api_?key|app_?secret|auth_?token|client_?secret|jwt_?secret|private_?key|supabase_?key|stripe_?key)\s*[:=]\s*(["'`])([a-zA-Z0-9_\-\.]{16,})\1/gi
    },
    {
      name: 'JWT Token expuesto',
      regex: /eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}/g
    },
    {
      name: 'Clave privada RSA/SSH',
      regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g
    }
  ];

  const extensions = ['.js', '.ts', '.html', '.php', '.json', '.env'];
  const findings = [];

  function walkDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Excluir dependencias, carpetas de compilación y caches pesados
        if (!['node_modules', '.git', 'vendor', 'dist', 'build', 'storage', '.next', '.turbo', '.output'].includes(entry.name)) {
          walkDir(fullPath);
        }
      } else if (extensions.includes(path.extname(entry.name).toLowerCase())) {
        const content = fs.readFileSync(fullPath, 'utf8');
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          const trimmed = line.trim();
          // Omitir comentarios de código
          if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) return;

          const lowerLine = line.toLowerCase();
          // Omitir declaraciones de claves de base de datos o esquemas
          if (ignoredProperties.some(prop => lowerLine.includes(prop))) return;

          for (const pattern of secretPatterns) {
            pattern.regex.lastIndex = 0;
            const match = pattern.regex.exec(line);

            if (match) {
              // Si es un patrón asignado, match[2] extrae el contenido exacto dentro de comillas
              const secretCandidate = match[2] || match[0];

              // Validar que realmente tenga características de secreto antes de alertar
              if (!isLikelyRealSecret(secretCandidate)) {
                continue;
              }

              findings.push({
                type: 'secret',
                category: 'Bloqueante',
                severity: 'CRITICAL',
                ruleId: `hardcoded-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
                path: path.relative(targetPath, fullPath),
                startLine: index + 1,
                message: `Credencial o clave hardcodeada detectada: "${pattern.name}". Debe transferirse a variables de entorno (.env).`,
                cwe: 'CWE-798',
                owasp: 'A07:2021-Identification and Authentication Failures'
              });
              break;
            }
          }
        });
      }
    }
  }

  try {
    walkDir(targetPath);
  } catch (e) {
    console.warn('⚠️ Error al escanear archivos locales:', e.message);
  }

  return findings;
}
// Configuración dinámica de paquetes Semgrep según el ecosistema
function getSemgrepConfigs(projectType) {
  // Base universal confiable
  const configs = ['--config=p/default'];

  if (projectType === 'node') {
    configs.push('--config=p/nodejs', '--config=p/javascript');
  } else if (projectType === 'php') {
    configs.push('--config=p/php');
  } else {
    configs.push('--config=p/javascript');
  }

  return configs.join(' ');
}

// Módulo SAST con Semgrep enriquecido con OWASP y CWE
async function runSemgrepScan(targetPath, projectType = 'static_web') {
  console.log(`⚡ Ejecutando análisis estático (Semgrep con perfiles para ${projectType})...`);
  const cleanTarget = path.resolve(targetPath);
  const configs = getSemgrepConfigs(projectType);
  const excludeFlags = '--exclude="dist" --exclude="build" --exclude=".next" --exclude="node_modules" --exclude="vendor" --exclude="storage"';

  const semgrepResult = await runCommand(
    `semgrep scan ${configs} ${excludeFlags} --json --quiet "${cleanTarget}"`,
    cleanTarget
  );

  let semgrepData = { results: [] };
  try {
    if (semgrepResult.stdout) {
      semgrepData = JSON.parse(semgrepResult.stdout);
    }
  } catch (e) {
    console.warn('⚠️ No se pudo parsear salida de Semgrep.');
  }

  // Mapeo y extracción de metadatos de ciberseguridad
  const semgrepFindings = (semgrepData.results || []).map(f => {
    const isError = (f.extra?.severity || '').toUpperCase() === 'ERROR';
    const metadata = f.extra?.metadata || {};
    const owasp = Array.isArray(metadata.owasp) ? metadata.owasp[0] : (metadata.owasp || null);
    const cwe = Array.isArray(metadata.cwe) ? metadata.cwe[0] : (metadata.cwe || null);

    return {
      type: 'sast',
      category: isError ? 'Bloqueante' : 'Advertencia',
      severity: isError ? 'ERROR' : 'WARNING',
      ruleId: f.check_id,
      path: path.relative(cleanTarget, f.path),
      startLine: f.start?.line || 1,
      message: f.extra?.message?.trim() || 'Problema de seguridad o buena práctica detectado.',
      owasp: owasp,
      cwe: cwe
    };
  });

  const localSecrets = scanCodeForSecrets(cleanTarget);
  const allFindings = [...localSecrets, ...semgrepFindings];

  const blockers = allFindings.filter(f => f.category === 'Bloqueante');
  const warnings = allFindings.filter(f => f.category === 'Advertencia');

  return {
    totalFindings: allFindings.length,
    blockersCount: blockers.length,
    warningsCount: warnings.length,
    blockers,
    warnings
  };
}

// Analizador para proyectos estáticos (HTML/CSS/JS)
async function auditStaticProject(targetPath) {
  console.log('⚡ Ejecutando escaneo para Proyecto Estático (HTML/CSS/JS)...');
  const sastReport = await runSemgrepScan(targetPath, 'static_web');

  const passed = sastReport.blockersCount === 0;

  return {
    projectType: 'static_web',
    scannedAt: new Date().toISOString(),
    standards: [
      'OWASP Top 10 Audited',
      'CWE Standards Compliance',
      'Secret Leakage Shield'
    ],
    summary: {
      passed,
      statusBadge: passed ? (sastReport.warningsCount > 0 ? 'APROBADO CON OBSERVACIONES' : 'APROBADO PARA ENTREGA') : 'REQUIERE REVISIÓN',
      totalBlockers: sastReport.blockersCount,
      totalWarnings: sastReport.warningsCount,
      totalVulnerabilities: 0
    },
    licenses: {
      totalFound: 0,
      allLicenses: ['N/A (Sin gestor de paquetes)'],
      hasRestrictedLicenses: false,
      restrictedFound: []
    },
    sast: sastReport
  };
}

// Analizador para proyectos Node.js / React / Angular
async function auditNodeProject(targetPath) {
  console.log('⚡ Ejecutando escaneo para Node.js...');

  const [auditRaw, licensesRaw, sastReport] = await Promise.all([
    runCommand('npm audit --json', targetPath),
    runCommand('npx license-checker --json', targetPath),
    runSemgrepScan(targetPath, 'node')
  ]);

  let auditData = { vulnerabilities: {}, metadata: {} };
  let licenseData = {};

  try {
    if (auditRaw.stdout) auditData = JSON.parse(auditRaw.stdout);
  } catch (e) {
    console.warn('⚠️ No se pudo parsear salida de npm audit.');
  }

  try {
    if (licensesRaw.stdout) licenseData = JSON.parse(licensesRaw.stdout);
  } catch (e) {
    console.warn('⚠️ No se pudo parsear salida de license-checker.');
  }

  // Parsear lista detallada de dependencias vulnerables
  const detailedVulns = [];
  const rawVulns = auditData.vulnerabilities || {};

  for (const [pkgName, details] of Object.entries(rawVulns)) {
    const isCritical = details.severity === 'critical' || details.severity === 'high';
    const fixText = details.fixAvailable === true 
      ? 'Actualización directa disponible vía npm audit fix' 
      : (typeof details.fixAvailable === 'object' 
          ? `Requiere actualizar a ${details.fixAvailable.name}@${details.fixAvailable.version} (breaking change)` 
          : 'Sin parche automático publicado aún');

    detailedVulns.push({
      type: 'dependency',
      category: isCritical ? 'Bloqueante' : 'Advertencia',
      severity: details.severity.toUpperCase(),
      ruleId: `npm-${pkgName}`,
      path: `package.json -> ${pkgName}`,
      startLine: 1,
      name: pkgName,
      range: details.range || 'N/A',
      fix: fixText,
      message: `Paquete vulnerable "${pkgName}". Severidad: ${details.severity}. Corrección: ${fixText}`
    });
  }

  const vulns = auditData.metadata?.vulnerabilities || auditData.vulnerabilities || {
    info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0
  };

  const licensesList = [...new Set(
    Object.values(licenseData).map(pkg => pkg.licenses).filter(Boolean)
  )];

  const restrictedLicenses = licensesList.filter(lic => /GPL|AGPL/i.test(lic));

  const criticalDependencies = (vulns.critical || 0) + (vulns.high || 0);
  const totalBlockers = sastReport.blockersCount + criticalDependencies + restrictedLicenses.length;
  const passed = totalBlockers === 0;

  return {
    projectType: 'node',
    scannedAt: new Date().toISOString(),
    standards: [
      'OWASP Top 10 Audited',
      'CWE Standards Compliance',
      'Secret Leakage Shield',
      'NPM Security Advisories'
    ],
    summary: {
      passed,
      statusBadge: passed ? (sastReport.warningsCount > 0 ? 'APROBADO CON OBSERVACIONES' : 'APROBADO PARA ENTREGA') : 'REQUIERE REVISIÓN',
      totalBlockers,
      totalWarnings: sastReport.warningsCount + (vulns.moderate || 0) + (vulns.low || 0),
      totalVulnerabilities: vulns.total || 0,
      criticalVulns: vulns.critical || 0,
      highVulns: vulns.high || 0
    },
    licenses: {
      totalFound: licensesList.length,
      allLicenses: licensesList,
      hasRestrictedLicenses: restrictedLicenses.length > 0,
      restrictedFound: restrictedLicenses
    },
    sast: sastReport,
    dependenciesVulnerabilities: detailedVulns
  };
}

// Analizador para proyectos PHP / Laravel
async function auditPhpProject(targetPath) {
  console.log('⚡ Ejecutando escaneo para PHP/Composer...');

  const [auditRaw, licensesRaw, sastReport] = await Promise.all([
    runCommand('composer audit --format=json', targetPath),
    runCommand('composer licenses --format=json', targetPath),
    runSemgrepScan(targetPath, 'php')
  ]);

  let auditData = { advisories: {} };
  let licenseData = { dependencies: {} };

  try {
    if (auditRaw.stdout) auditData = JSON.parse(auditRaw.stdout);
  } catch (e) {
    console.warn('⚠️ No se pudo parsear salida de composer audit.');
  }

  try {
    if (licensesRaw.stdout) licenseData = JSON.parse(licensesRaw.stdout);
  } catch (e) {
    console.warn('⚠️ No se pudo parsear salida de composer licenses.');
  }

  const advisoriesCount = Object.keys(auditData.advisories || {}).length;
  const packageLicenses = Object.values(licenseData.dependencies || {}).flatMap(dep => dep.license || []);
  const licensesList = [...new Set(packageLicenses)];
  const restrictedLicenses = licensesList.filter(lic => /GPL|AGPL/i.test(lic));

  const totalBlockers = sastReport.blockersCount + advisoriesCount + restrictedLicenses.length;
  const passed = totalBlockers === 0;

  return {
    projectType: 'php',
    scannedAt: new Date().toISOString(),
    standards: [
      'OWASP Top 10 Audited',
      'CWE Standards Compliance',
      'Secret Leakage Shield',
      'Composer Security Advisories'
    ],
    summary: {
      passed,
      statusBadge: passed ? (sastReport.warningsCount > 0 ? 'APROBADO CON OBSERVACIONES' : 'APROBADO PARA ENTREGA') : 'REQUIERE REVISIÓN',
      totalBlockers,
      totalWarnings: sastReport.warningsCount,
      totalAdvisories: advisoriesCount
    },
    licenses: {
      totalFound: licensesList.length,
      allLicenses: licensesList,
      hasRestrictedLicenses: restrictedLicenses.length > 0,
      restrictedFound: restrictedLicenses
    },
    sast: sastReport,
    advisories: auditData.advisories || {}
  };
}

// Orquestador principal
async function scanProject(targetInput, token = null) {
  const inputStr = targetInput ? targetInput.trim() : './';
  const isGit = /^https?:\/\/(www\.)?github\.com\/.+/i.test(inputStr);
  const isZip = inputStr.toLowerCase().endsWith('.zip');

  let workingDir = inputStr;
  let isTempDir = false;

  try {
    if (isGit) {
      workingDir = await cloneGitHubRepo(inputStr, token);
      isTempDir = true;
    } else if (isZip) {
      workingDir = extractZipArchive(path.resolve(inputStr));
      isTempDir = true;
    }

    const absolutePath = path.resolve(workingDir);

    if (!fs.existsSync(absolutePath)) {
      console.error(`❌ El directorio de trabajo "${absolutePath}" no existe.`);
      process.exit(1);
    }

    console.log(`🔍 Iniciando análisis en: ${isGit ? inputStr : absolutePath}`);

    const hasPackageJson = fs.existsSync(path.join(absolutePath, 'package.json'));
    const hasComposerJson = fs.existsSync(path.join(absolutePath, 'composer.json'));

    let report = null;

    if (hasPackageJson) {
      report = await auditNodeProject(absolutePath);
    } else if (hasComposerJson) {
      report = await auditPhpProject(absolutePath);
    } else {
      report = await auditStaticProject(absolutePath);
    }

    if (isGit) report.source = { type: 'git', target: inputStr };
    else if (isZip) report.source = { type: 'zip', target: path.basename(inputStr) };
    else report.source = { type: 'local', target: absolutePath };

    const outputPath = path.join(__dirname, 'scan-report.json');
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));

    console.log('\n✅ Análisis completado con éxito.');
    console.log(`📄 Reporte guardado en: ${outputPath}\n`);
    console.log('--- RESUMEN ---');
    console.log(`Origen: ${report.source.type} -> ${report.source.target}`);
    console.log(`Tipo de proyecto: ${report.projectType}`);
    console.log(`Estado: ${report.summary.passed ? '🟢 ' + report.summary.statusBadge : '🔴 ' + report.summary.statusBadge}`);
    console.log(`Fallos Bloqueantes: ${report.summary.totalBlockers}`);
    console.log(`Observaciones / Advertencias: ${report.summary.totalWarnings}`);

    return report;

  } catch (error) {
    console.error(`❌ Error durante el escaneo: ${error.message}`);
    throw error;
  } finally {
    if (isTempDir && workingDir) {
      cleanupTempDir(workingDir);
    }
  }
}

// Ejecución directa por CLI
if (require.main === module) {
  const targetPath = process.argv[2] || './';
  const gitToken = process.argv[3] || null;
  scanProject(targetPath, gitToken);
}

module.exports = { scanProject };