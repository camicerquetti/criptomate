import React, { useState } from 'react';
import { Container, TextField, Button, Box, Typography, Grid, Snackbar, Alert } from '@mui/material';
import "../App.css"

const FormularioContacto = () => {
  const [formData, setFormData] = useState({
    nombre: '',
    correo: '',
    mensaje: ''
  });
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('success');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch('http://localhost:3001/api/contact', { // Ajusta la URL si es necesario
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });

      const result = await response.json();

      if (response.ok) {
        setSnackbarMessage('Mensaje enviado con éxito.');
        setSnackbarSeverity('success');
      } else {
        setSnackbarMessage(result.error || 'Error al enviar el mensaje.');
        setSnackbarSeverity('error');
      }

      setOpenSnackbar(true);

      // Limpiar formulario después del envío
      setFormData({
        nombre: '',
        correo: '',
        mensaje: ''
      });
    } catch (error) {
      setSnackbarMessage('Error de red. No se pudo enviar el mensaje.');
      setSnackbarSeverity('error');
      setOpenSnackbar(true);
      console.error('Error al enviar el mensaje:', error);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box className="formulario">
        <Typography variant="h4" component="h1" gutterBottom align="center">
          Contáctanos
        </Typography>
        <form onSubmit={handleSubmit}>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Nombre"
                name="nombre"
                variant="outlined"
                value={formData.nombre}
                onChange={handleChange}
                required
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Correo Electrónico"
                name="correo"
                type="email"
                variant="outlined"
                value={formData.correo}
                onChange={handleChange}
                required
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Mensaje"
                name="mensaje"
                variant="outlined"
                multiline
                rows={4}
                value={formData.mensaje}
                onChange={handleChange}
                required
              />
            </Grid>
            <Grid item xs={12} sx={{ textAlign: 'center' }}>
              <Button class="but" type="submit" variant="contained" color="primary" size="large">
                Enviar Mensaje
              </Button>
            </Grid>
          </Grid>
        </form>
        <Snackbar
          open={openSnackbar}
          autoHideDuration={6000}
          onClose={() => setOpenSnackbar(false)}
          message={snackbarMessage}
        >
          <Alert onClose={() => setOpenSnackbar(false)} severity={snackbarSeverity}>
            {snackbarMessage}
          </Alert>
        </Snackbar>
      </Box>
    </Container>
  );
};

export default FormularioContacto;
