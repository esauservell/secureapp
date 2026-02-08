const express = require('express');
const bodyParser = require('body-parser');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const xss = require('xss');
const app = express();
const port = process.env.PORT || 3000;

app.set('trust proxy', true);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());

app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "frame-ancestors": ["'self'"],
      "img-src": ["'self'", "data:"],
      "style-src": ["'self'", "'unsafe-inline'"], 
      "upgrade-insecure-requests": [] 
    },
  })
);

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});
const dbUser = process.env.DB_USER || process.env.USER;
const dbPass = process.env.DB_PASS || process.env.PASS;

const config = {
  server: process.env.SERVER_DB,           
  database: process.env.NOMBRE_DB,         
  authentication: {
    type: 'default',
    options: {
      userName: dbUser,
      password: dbPass
    }
  },
  options: {
    encrypt: true,                         
    trustServerCertificate: false,
    port: parseInt(process.env.PORT_DB, 10) || 1433
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};
app.get('/', (req, res) => {
  res.type('html').send(`
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Registro</title>
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, Arial, sans-serif; margin: 2rem; }
    form { max-width: 420px; }
    input, button { width: 100%; padding: .6rem; margin: .3rem 0; }
    button { background: #2563eb; color: white; border: 0; border-radius: .25rem; cursor: pointer; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <h1>Registro</h1>
  <form method="POST" action="/comentario" autocomplete="off">
    <input type="text" name="nombre" placeholder="Nombre" required>
    <input type="text" name="apellido" placeholder="Apellido" required>
    <input type="text" name="usuario" placeholder="Usuario" required>
    <input type="password" name="contrasena" placeholder="Contraseña" required>
    <button type="submit">Enviar</button>
  </form>
</body>
</html>
  `);
});
app.post('/comentario', async (req, res) => {
  const nombre     = xss(req.body?.nombre ?? '');
  const apellido   = xss(req.body?.apellido ?? '');
  const usuario    = xss(req.body?.usuario ?? '');
  const contrasena = req.body?.contrasena ?? '';

  if (!nombre || !apellido || !usuario || !contrasena) {
    return res.status(400).send('Faltan campos requeridos.');
  }

  if (nombre.length > 200 || apellido.length > 200 || usuario.length > 200) {
    return res.status(400).send('Los campos no deben exceder 200 caracteres.');
  }

  try {

    const hashedPassword = await bcrypt.hash(contrasena, 10);
    const pool = await sql.connect(config);

    await pool.request()
      .input('nombre',    sql.NVarChar, nombre)
      .input('apellido',  sql.NVarChar, apellido)
      .input('usuario',   sql.NVarChar, usuario)
      .input('contrasena',sql.NVarChar, hashedPassword)
      .query(`
        INSERT INTO Comentarios (Nombre, Apellido, Usuario, Contrasena)
        VALUES (@nombre, @apellido, @usuario, @contrasena)
      `);

    res.type('html').send(`
      <!doctype html>
      <html lang="es"><head><meta charset="utf-8"><title>OK</title></head>
      <body style="font-family: system-ui, Arial, sans-serif; margin:2rem">
        <h2>Datos guardados exitosamente.</h2>
        <p><a href="/">Volver</a></p>
      </body></html>
    `);
  } catch (err) {
    console.error('[ERROR /comentario]', err);
    res.status(500).send('Error en el servidor.');
  }
});
app.use((err, req, res, next) => {
  console.error('[UNCAUGHT ERROR]', err);
  res.status(500).send('Error inesperado.');
});
app.listen(port, () => {
  console.log(`App corriendo en puerto ${port}`);
});
