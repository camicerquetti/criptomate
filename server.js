const express = require('express');
const cors = require('cors');
const path = require('path');
const db = require('./config/db'); 
const userRoutes = require('./routes/userRoutes');
const app = express();
const port = process.env.PORT || 3001; // Usa el puerto del entorno o un puerto por defecto
const nodemailer = require('nodemailer');
require('dotenv').config();

// Configura CORS
app.use(cors({
  origin: 'http://localhost:3000', // Permite solicitudes desde este origen
}));

// Configura el middleware para manejar JSON
app.use(express.json()); // Para manejar solicitudes JSON

// Usa las rutas del usuario antes de servir archivos estáticos
app.use('/api', userRoutes); // '/api' es el prefijo para tus rutas

// Define el directorio de archivos estáticos
const staticPath = path.join(__dirname, '../front-end/build');

// Verifica la ruta de los archivos estáticos
console.log('Serving static files from:', staticPath);

// Sirve archivos estáticos desde la carpeta build del frontend
app.use(express.static(staticPath));

// Ruta para manejar el acceso a la SPA (Single Page Application)
app.get('*', (req, res) => {
  // Construye la ruta al archivo index.html
  const filePath = path.join(staticPath, 'index.html');
  console.log('Requesting file:', filePath); // Log para depuración
  
  // Envía el archivo index.html si existe
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error('Error sending file:', err);
      res.status(err.status || 500).send('Something went wrong!');
    }
  });
});

// Manejo de errores
app.use((err, req, res, next) => {
  console.error('Error stack:', err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});
