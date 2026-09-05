const express = require('express');
const multer = require('multer');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { scanProject } = require('./Orchestrator.js');

const app = express();

// Security limit for local ZIP uploads (50 MB)
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

const VALID_ENVIRONMENTS = ['node', 'php', 'static_web'];

// Base middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// 1. Audit an existing local directory on the user's filesystem
app.post('/api/audit/folder', async (req, res) => {
  const { folderPath, projectType } = req.body;

  if (!folderPath || typeof folderPath !== 'string') {
    return res.status(400).json({ error: 'Folder path is required.' });
  }

  if (!projectType || !VALID_ENVIRONMENTS.includes(projectType)) {
    return res.status(400).json({
      error: `You must select a valid project type: ${VALID_ENVIRONMENTS.join(', ')}`
    });
  }

  const resolvedPath = path.resolve(folderPath.trim());
  if (!fs.existsSync(resolvedPath)) {
    return res.status(400).json({ error: `The path "${resolvedPath}" does not exist on this machine.` });
  }

  try {
    const reportData = await scanProject(resolvedPath, projectType);
    res.json({ success: true, data: reportData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Audit a local ZIP archive
app.post('/api/audit/zip', upload.single('projectZip'), async (req, res) => {
  const { projectType } = req.body;

  if (!projectType || !VALID_ENVIRONMENTS.includes(projectType)) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(400).json({
      error: `You must select a valid project type: ${VALID_ENVIRONMENTS.join(', ')}`
    });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Please select a .zip file to audit.' });
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

// Allows direct execution or CLI binary import
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`[INFO] Auditor Web UI active on http://localhost:${PORT}`);
  });
}

module.exports = app;