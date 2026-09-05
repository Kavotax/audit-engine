const express = require('express');
const multer = require('multer');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { scanProject } = require('./Orchestrator.js');

const app = express();

// Límite de seguridad para carga de ZIPs en local (ej. 50 MB)
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

const VALID_ENVIRONMENTS = ['node', 'php', 'static_web'];

// Middlewares base
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// 1. Auditar carpeta local existente en el disco del usuario
app.post('/api/audit/folder', async (req, res) => {
  const { folderPath, projectType } = req.body;

  if (!folderPath || typeof folderPath !== 'string') {
    return res.status(400).json({ error: 'La ruta de la carpeta es obligatoria.' });
  }

  if (!projectType || !VALID_ENVIRONMENTS.includes(projectType)) {
    return res.status(400).json({
      error: `Debes seleccionar un tipo de proyecto válido: ${VALID_ENVIRONMENTS.join(', ')}`
    });
  }

  const resolvedPath = path.resolve(folderPath.trim());
  if (!fs.existsSync(resolvedPath)) {
    return res.status(400).json({ error: `La ruta "${resolvedPath}" no existe en este equipo.` });
  }

  try {
    const reportData = await scanProject(resolvedPath, projectType);
    res.json({ success: true, data: reportData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Auditar repositorio remoto vía Git local (HTTPS o SSH)
app.post('/api/audit/git', async (req, res) => {
  const { repoUrl, projectType } = req.body;

  if (!repoUrl || typeof repoUrl !== 'string') {
    return res.status(400).json({ error: 'La URL o ruta del repositorio es obligatoria.' });
  }

  if (!projectType || !VALID_ENVIRONMENTS.includes(projectType)) {
    return res.status(400).json({
      error: `Debes seleccionar un tipo de proyecto válido: ${VALID_ENVIRONMENTS.join(', ')}`
    });
  }

  try {
    const reportData = await scanProject(repoUrl.trim(), projectType);
    res.json({ success: true, data: reportData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Auditar archivo ZIP
app.post('/api/audit/zip', upload.single('projectZip'), async (req, res) => {
  const { projectType } = req.body;

  if (!projectType || !VALID_ENVIRONMENTS.includes(projectType)) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(400).json({
      error: `Debes seleccionar un tipo de proyecto válido: ${VALID_ENVIRONMENTS.join(', ')}`
    });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Debes seleccionar un archivo .zip para auditar.' });
  }

  const zipTempPath = `${req.file.path}.zip`;
  fs.renameSync(req.file.path, zipTempPath);

  try {
    const reportData = await scanProject(zipTempPath, projectType);
    res.json({ success: true, data: reportData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (fs.existsSync(zipTempPath)) {
      fs.unlinkSync(zipTempPath);
    }
  }
});

// Permite ejecutar directo o importar desde el binario CLI
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Auditor Web UI activo en http://localhost:${PORT}`);
  });
}

module.exports = app;