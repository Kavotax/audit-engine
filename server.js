require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cookieSession = require('cookie-session');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { scanProject } = require('./Orchestrator.js');

const app = express();
const upload = multer({ dest: os.tmpdir() });

// 1. Middlewares globales (deben ir antes de cualquier ruta)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieSession({
  name: 'audit_session',
  keys: [process.env.SESSION_SECRET || 'clave_secreta_temporal_12345'],
  maxAge: 24 * 60 * 60 * 1000 // 24 horas
}));

app.use(express.static(path.join(__dirname, 'public')));

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

// 2. Ruta para iniciar login con GitHub
app.get('/api/auth/github', (req, res) => {
  if (!GITHUB_CLIENT_ID) {
    return res.status(500).send('Error: GITHUB_CLIENT_ID no está configurado en el archivo .env');
  }
  const redirectUri = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=repo`;
  res.redirect(redirectUri);
});

// 3. Callback OAuth de GitHub (cierra popup y notifica)
app.get('/api/auth/github/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.send('<script>window.close();</script>');
  }

  try {
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      })
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.access_token) {
      req.session = req.session || {};
      req.session.githubToken = tokenData.access_token;
    }

    res.send(`
      <script>
        if (window.opener) {
          window.opener.postMessage('github_auth_success', '*');
        }
        window.close();
      </script>
    `);
  } catch (err) {
    console.error('Error al intercambiar token:', err.message);
    res.send('<script>window.close();</script>');
  }
});

// 4. Obtener repositorios y validar sesión de forma segura
app.get('/api/github/user-repos', async (req, res) => {
  try {
    const token = (req.session && req.session.githubToken) ? req.session.githubToken : null;
    if (!token) {
      return res.json({ authenticated: false, repos: [] });
    }

    const [userRes, reposRes] = await Promise.all([
      fetch('https://api.github.com/user', {
        headers: { 'Authorization': `Bearer ${token}`, 'User-Agent': 'AuditorEngine' }
      }),
      fetch('https://api.github.com/user/repos?sort=updated&per_page=50', {
        headers: { 'Authorization': `Bearer ${token}`, 'User-Agent': 'AuditorEngine' }
      })
    ]);

    if (!userRes.ok) {
      if (req.session) req.session = null;
      return res.json({ authenticated: false, repos: [] });
    }

    const userData = await userRes.json();
    const reposData = await reposRes.json();

    return res.json({
      authenticated: true,
      username: userData.login || 'Usuario',
      repos: Array.isArray(reposData) ? reposData.map(r => ({
        id: r.id,
        name: r.full_name,
        private: r.private,
        clone_url: r.clone_url
      })) : []
    });
  } catch (err) {
    console.error('Error en /api/github/user-repos:', err.message);
    return res.json({ authenticated: false, repos: [], error: err.message });
  }
});

// 5. Logout
app.get('/api/auth/github/logout', (req, res) => {
  req.session = null;
  res.json({ success: true });
});

// 6. Auditar repositorio
app.post('/api/audit/git', async (req, res) => {
  const { repoUrl } = req.body;
  const sessionToken = (req.session && req.session.githubToken) ? req.session.githubToken : null;

  if (!repoUrl) {
    return res.status(400).json({ error: 'La URL del repositorio es requerida.' });
  }

  try {
    const reportData = await scanProject(repoUrl.trim(), sessionToken);
    res.json({ success: true, data: reportData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Auditar archivo ZIP
app.post('/api/audit/zip', upload.single('projectZip'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Selecciona un archivo .zip' });
  }

  const zipTempPath = `${req.file.path}.zip`;
  fs.renameSync(req.file.path, zipTempPath);

  try {
    const reportData = await scanProject(zipTempPath);
    res.json({ success: true, data: reportData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (fs.existsSync(zipTempPath)) {
      fs.unlinkSync(zipTempPath);
    }
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Auditor Web UI activo en http://localhost:${PORT}`);
});