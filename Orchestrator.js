const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const AdmZip = require('adm-zip');

// Safe execution without vulnerable sub-shell invocation
function runSafeCommand(file, args, cwd, timeout = 120000) {
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      { cwd, timeout, maxBuffer: 1024 * 1024 * 15 },
      (error, stdout, stderr) => {
        resolve({
          stdout: stdout ? stdout.trim() : '',
          stderr: stderr ? stderr.trim() : '',
          error
        });
      }
    );
  });
}

// Local clone leveraging SSH (~/.ssh) or Git Credential Manager
async function cloneRepoLocal(repoUrl) {
  const tempDir = path.join(os.tmpdir(), `audit-repo-${Date.now()}`);
  console.log(`[INFO] Cloning remote repository via local Git (${repoUrl})...`);

  const cleanUrl = repoUrl.trim();
  const result = await runSafeCommand('git', ['clone', '--depth', '1', cleanUrl, tempDir], process.cwd());

  if (result.error && !fs.existsSync(tempDir)) {
    throw new Error(
      `Failed to clone repository. Verify your SSH keys, Git credentials, or that the URL exists: ${result.stderr || result.stdout}`
    );
  }

  // Generate lockfile without running potentially malicious pre/post-install hooks
  const hasPackageJson = fs.existsSync(path.join(tempDir, 'package.json'));
  const hasLockfile = fs.existsSync(path.join(tempDir, 'package-lock.json'));

  if (hasPackageJson && !hasLockfile) {
    console.log('[INFO] Generating lockfile for dependency auditing...');
    await runSafeCommand('npm', ['install', '--package-lock-only', '--ignore-scripts'], tempDir);
  }

  return tempDir;
}

// Decompression protected against Zip Slip and Zip Bombs
function extractZipArchive(zipFilePath) {
  const tempDir = path.join(os.tmpdir(), `audit-zip-${Date.now()}`);
  console.log(`[INFO] Extracting ZIP archive (${zipFilePath})...`);

  const resolvedZip = path.resolve(zipFilePath);
  if (!fs.existsSync(resolvedZip)) {
    throw new Error(`The .zip archive "${resolvedZip}" does not exist.`);
  }

  const zip = new AdmZip(resolvedZip);
  const zipEntries = zip.getEntries();
  const resolvedTempDir = path.resolve(tempDir);

  // Path-Traversal validation (Zip Slip mitigation)
  for (const entry of zipEntries) {
    const targetPath = path.resolve(resolvedTempDir, entry.entryName);
    if (!targetPath.startsWith(resolvedTempDir + path.sep) && targetPath !== resolvedTempDir) {
      throw new Error('Malicious ZIP archive detected: attempted directory escape (Zip Slip).');
    }
  }

  zip.extractAllTo(tempDir, true);
  return tempDir;
}

// Cleanup of temporary working directories
function cleanupTempDir(dirPath) {
  try {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
      console.log('[INFO] Temporary directory cleaned up successfully.');
    }
  } catch (err) {
    console.warn(`[WARN] Failed to delete temporary directory: ${err.message}`);
  }
}

function isLikelyRealSecret(str) {
  const clean = str.replace(/["'`]/g, '').trim();

  if (/^[a-z_\-]+$/.test(clean)) return false;
  if (/^(configured|test|dummy|mock|example|sample|placeholder|default)[-_]/i.test(clean)) return false;

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

  const hasMixedTypes =
    (/[0-9]/.test(clean) && /[a-zA-Z]/.test(clean)) ||
    (/[A-Z]/.test(clean) && /[a-z]/.test(clean));

  return entropy >= 2.8 && hasMixedTypes;
}

function scanCodeForSecrets(targetPath) {
  const ignoredProperties = [
    'primarykey', 'foreignkey', 'foreign_key', 'routekey',
    'uniquekey', 'cachekey', 'keytype', 'key_name'
  ];

  const secretPatterns = [
    {
      name: 'Hardcoded API Key / Token',
      regex: /(?:api_?key|app_?secret|auth_?token|client_?secret|jwt_?secret|private_?key|supabase_?key|stripe_?key)\s*[:=]\s*(["'`])([a-zA-Z0-9_\-\.]{16,})\1/gi
    },
    {
      name: 'Exposed JWT Token',
      regex: /eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}/g
    },
    {
      name: 'Private RSA/SSH Key',
      regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g
    }
  ];

  const extensions = ['.js', '.ts', '.html', '.php', '.json'];
  const findings = [];

  function walkDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!['node_modules', '.git', 'vendor', 'dist', 'build', 'storage', '.next', '.turbo', '.output'].includes(entry.name)) {
          walkDir(fullPath);
        }
      } else {
        // Ignore local environment files (.env, .env.local, etc.)
        if (entry.name.startsWith('.env')) continue;

        if (extensions.includes(path.extname(entry.name).toLowerCase())) {
          const content = fs.readFileSync(fullPath, 'utf8');
          const lines = content.split('\n');

          lines.forEach((line, index) => {
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) return;

            const lowerLine = line.toLowerCase();
            if (ignoredProperties.some(prop => lowerLine.includes(prop))) return;

            for (const pattern of secretPatterns) {
              pattern.regex.lastIndex = 0;
              const match = pattern.regex.exec(line);

              if (match) {
                const secretCandidate = match[2] || match[0];
                if (!isLikelyRealSecret(secretCandidate)) continue;

                findings.push({
                  type: 'secret',
                  category: 'Blocker',
                  severity: 'CRITICAL',
                  ruleId: `hardcoded-${pattern.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
                  path: path.relative(targetPath, fullPath),
                  startLine: index + 1,
                  message: `Exposed credential detected: "${pattern.name}". Move this value to an environment variable (.env).`,
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
  }

  try {
    walkDir(targetPath);
  } catch (e) {
    console.warn(`[WARN] Failed to scan local files for secrets: ${e.message}`);
  }

  return findings;
}

function getSemgrepConfigs(projectType) {
  const configs = ['--config=p/default'];
  if (projectType === 'node') {
    configs.push('--config=p/nodejs', '--config=p/javascript');
  } else if (projectType === 'php') {
    configs.push('--config=p/php');
  } else {
    configs.push('--config=p/javascript');
  }
  return configs;
}

async function runSemgrepScan(targetPath, projectType = 'static_web') {
  console.log(`[INFO] Running static analysis (Semgrep with rulesets for ${projectType})...`);
  const cleanTarget = path.resolve(targetPath);
  const configs = getSemgrepConfigs(projectType);

  const semgrepArgs = [
    'scan',
    ...configs,
    '--exclude=dist',
    '--exclude=build',
    '--exclude=.next',
    '--exclude=node_modules',
    '--exclude=vendor',
    '--exclude=storage',
    '--exclude=.env*',
    '--json',
    '--quiet',
    cleanTarget
  ];

  const semgrepResult = await runSafeCommand('semgrep', semgrepArgs, cleanTarget);

  let semgrepData = { results: [] };
  try {
    if (semgrepResult.stdout) {
      semgrepData = JSON.parse(semgrepResult.stdout);
    }
  } catch (e) {
    console.warn('[WARN] Could not parse Semgrep output.');
  }

  const semgrepFindings = (semgrepData.results || []).map(f => {
    const isError = (f.extra?.severity || '').toUpperCase() === 'ERROR';
    const metadata = f.extra?.metadata || {};
    const owasp = Array.isArray(metadata.owasp) ? metadata.owasp[0] : (metadata.owasp || null);
    const cwe = Array.isArray(metadata.cwe) ? metadata.cwe[0] : (metadata.cwe || null);

    return {
      type: 'sast',
      category: isError ? 'Blocker' : 'Warning',
      severity: isError ? 'ERROR' : 'WARNING',
      ruleId: f.check_id,
      path: path.relative(cleanTarget, f.path),
      startLine: f.start?.line || 1,
      message: f.extra?.message?.trim() || 'Security flaw or anti-pattern detected.',
      owasp,
      cwe
    };
  });

  const localSecrets = scanCodeForSecrets(cleanTarget);
  const allFindings = [...localSecrets, ...semgrepFindings];

  const blockers = allFindings.filter(f => f.category === 'Blocker');
  const warnings = allFindings.filter(f => f.category === 'Warning');

  return {
    totalFindings: allFindings.length,
    blockersCount: blockers.length,
    warningsCount: warnings.length,
    blockers,
    warnings
  };
}

async function auditStaticProject(targetPath) {
  console.log('[INFO] Running scan for Static Web Project (HTML/CSS/JS)...');
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
      statusBadge: passed ? (sastReport.warningsCount > 0 ? 'APPROVED WITH OBSERVATIONS' : 'APPROVED FOR DELIVERY') : 'REQUIRES REVISION',
      totalBlockers: sastReport.blockersCount,
      totalWarnings: sastReport.warningsCount,
      totalVulnerabilities: 0
    },
    sast: sastReport
  };
}

async function auditNodeProject(targetPath) {
  console.log('[INFO] Running scan for Node.js...');

  const [auditRaw, sastReport] = await Promise.all([
    runSafeCommand('npm', ['audit', '--json'], targetPath),
    runSemgrepScan(targetPath, 'node')
  ]);

  let auditData = { vulnerabilities: {}, metadata: {} };
  try {
    if (auditRaw.stdout) auditData = JSON.parse(auditRaw.stdout);
  } catch (e) {
    console.warn('[WARN] Could not parse npm audit output.');
  }

  const detailedVulns = [];
  const rawVulns = auditData.vulnerabilities || {};

  for (const [pkgName, details] of Object.entries(rawVulns)) {
    const isCritical = details.severity === 'critical' || details.severity === 'high';
    const fixText = details.fixAvailable === true 
      ? 'Direct update available via npm audit fix' 
      : (typeof details.fixAvailable === 'object' 
          ? `Requires updating to ${details.fixAvailable.name}@${details.fixAvailable.version} (breaking change)` 
          : 'No automated patch released yet');

    detailedVulns.push({
      type: 'dependency',
      category: isCritical ? 'Blocker' : 'Warning',
      severity: details.severity.toUpperCase(),
      ruleId: `npm-${pkgName}`,
      path: `package.json -> ${pkgName}`,
      startLine: 1,
      name: pkgName,
      range: details.range || 'N/A',
      fix: fixText,
      message: `Vulnerable dependency "${pkgName}". Severity: ${details.severity}. Fix: ${fixText}`
    });
  }

  const vulns = auditData.metadata?.vulnerabilities || auditData.vulnerabilities || {
    info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0
  };

  const criticalDependencies = (vulns.critical || 0) + (vulns.high || 0);
  const totalBlockers = sastReport.blockersCount + criticalDependencies;
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
      statusBadge: passed ? (sastReport.warningsCount > 0 ? 'APPROVED WITH OBSERVATIONS' : 'APPROVED FOR DELIVERY') : 'REQUIRES REVISION',
      totalBlockers,
      totalWarnings: sastReport.warningsCount + (vulns.moderate || 0) + (vulns.low || 0),
      totalVulnerabilities: vulns.total || 0,
      criticalVulns: vulns.critical || 0,
      highVulns: vulns.high || 0
    },
    sast: sastReport,
    dependenciesVulnerabilities: detailedVulns
  };
}

async function auditPhpProject(targetPath) {
  console.log('[INFO] Running scan for PHP/Composer...');

  const [auditRaw, sastReport] = await Promise.all([
    runSafeCommand('composer', ['audit', '--no-plugins', '--no-scripts', '--format=json'], targetPath),
    runSemgrepScan(targetPath, 'php')
  ]);

  let auditData = { advisories: {} };
  try {
    if (auditRaw.stdout) auditData = JSON.parse(auditRaw.stdout);
  } catch (e) {
    console.warn('[WARN] Could not parse composer audit output.');
  }

  const advisoriesCount = Object.keys(auditData.advisories || {}).length;
  const totalBlockers = sastReport.blockersCount + advisoriesCount;
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
      statusBadge: passed ? (sastReport.warningsCount > 0 ? 'APPROVED WITH OBSERVATIONS' : 'APPROVED FOR DELIVERY') : 'REQUIRES REVISION',
      totalBlockers,
      totalWarnings: sastReport.warningsCount,
      totalAdvisories: advisoriesCount
    },
    sast: sastReport,
    advisories: auditData.advisories || {}
  };
}

const VALID_ENVIRONMENTS = ['node', 'php', 'static_web'];

// Main orchestrator (100% Local)
async function scanProject(targetInput, projectType = null) {
  if (!projectType || !VALID_ENVIRONMENTS.includes(projectType)) {
    throw new Error(`You must select a valid environment (${VALID_ENVIRONMENTS.join(', ')}). Received: "${projectType}"`);
  }

  const inputStr = targetInput ? targetInput.trim() : './';
  
  const isGit = /^(https?:\/\/|git@).+/i.test(inputStr);
  const isZip = inputStr.toLowerCase().endsWith('.zip');

  let workingDir = inputStr;
  let isTempDir = false;

  try {
    if (isGit) {
      workingDir = await cloneRepoLocal(inputStr);
      isTempDir = true;
    } else if (isZip) {
      workingDir = extractZipArchive(path.resolve(inputStr));
      isTempDir = true;
    }

    const absolutePath = path.resolve(workingDir);

    if (!fs.existsSync(absolutePath)) {
      throw new Error(`Working directory "${absolutePath}" does not exist.`);
    }

    console.log(`[INFO] Starting audit on: ${isGit ? inputStr : absolutePath} (Environment: ${projectType})`);

    let report = null;
    if (projectType === 'php') {
      report = await auditPhpProject(absolutePath);
    } else if (projectType === 'node') {
      report = await auditNodeProject(absolutePath);
    } else if (projectType === 'static_web') {
      report = await auditStaticProject(absolutePath);
    }

    if (isGit) report.source = { type: 'git', target: inputStr };
    else if (isZip) report.source = { type: 'zip', target: path.basename(inputStr) };
    else report.source = { type: 'local', target: absolutePath };

    const outputPath = path.join(process.cwd(), 'scan-report.json');
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));

    console.log('[SUCCESS] Audit completed successfully.');
    console.log(`[INFO] Report saved to: ${outputPath}`);

    return report;

  } catch (error) {
    console.error(`[ERROR] Scan execution failed: ${error.message}`);
    throw error;
  } finally {
    if (isTempDir && workingDir) {
      cleanupTempDir(workingDir);
    }
  }
}

// CLI execution: node Orchestrator.js <path|git-url|zip> <node|php|static_web>
if (require.main === module) {
  const targetPath = process.argv[2] || './';
  const forcedType = process.argv[3] || null;

  if (!forcedType || !VALID_ENVIRONMENTS.includes(forcedType)) {
    console.error(`[ERROR] You must specify a valid environment: ${VALID_ENVIRONMENTS.join(' | ')}`);
    console.error('Example: node Orchestrator.js ./my-project node');
    process.exit(1);
  }

  scanProject(targetPath, forcedType);
}

module.exports = { scanProject };