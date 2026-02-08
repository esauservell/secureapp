const express = require('express');
const bodyParser = require('body-parser');
const sql = require('mssql');
const bcrypt = require('bcrypt'); 
const app = express();
const port = process.env.PORT || 3000;
app.use(bodyParser.urlencoded({ extended: true }));

const config = {
   server: process.env.SERVER_DB,
   database: process.env.NOMBRE_DB,
   authentication: {
       type: 'default',
       options: {
           userName: process.env.USER,
           password: process.env.PASS
       }
   },
   options: {
       encrypt: true,
       trustServerCertificate: false,
       port: parseInt(process.env.PORT_DB) || 1433
   },
};

app.get('/', (req, res) => {
   res.send(`
<h1>Registro</h1>
<form method="POST" action="/comentario">
<input type="text" name="nombre" placeholder="Nombre" required><br>
<input type="text" name="apellido" placeholder="Apellido" required><br>
<input type="text" name="usuario" placeholder="Usuario" required><br>
<input type="password" name="contrasena" placeholder="Contraseña" required><br>
<button type="submit">Enviar</button>
</form>
   `);
});

app.post('/comentario', async (req, res) => {
   const { nombre, apellido, usuario, contrasena } = req.body;
   try {
       const hashedPassword = await bcrypt.hash(contrasena, 10);
       let pool = await sql.connect(config);
       await pool.request()
           .input('nombre', sql.NVarChar, nombre)
           .input('apellido', sql.NVarChar, apellido)
           .input('usuario', sql.NVarChar, usuario)
           .input('contrasena', sql.NVarChar, hashedPassword)
           .query(`INSERT INTO Comentarios (Nombre, Apellido, Usuario, Contrasena)
                   VALUES (@nombre, @apellido, @usuario, @contrasena)`);
       res.send("Datos guardados exitosamente.");
   } catch (err) {
       console.error(err);
       res.status(500).send("Error en el servidor.");
   }
});
app.listen(port, () => console.log(`App corriendo en puerto ${port}`));