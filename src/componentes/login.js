import React, { useState } from 'react';
import { TextField, Button, Typography, Container, Box } from '@mui/material';
import { useNavigate } from 'react-router-dom'; // Para redireccionar al usuario
import '../App.css'; // Asegúrate de tener este archivo CSS

const LoginForm = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate(); // Hook para redirigir al usuario

  const handleSubmit = async (event) => {
    event.preventDefault();

    setError('');
    setSuccess('');

    try {
      const response = await fetch('http://localhost:3001/api/login', { // Ajusta la URL según tu configuración
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Login successful');
        localStorage.setItem('token', data.token); // Guardar el token en localStorage
        localStorage.setItem('userId', data.userId); // Guardar el userId en localStorage

        // Log para verificar si se llega a esta línea
        console.log('Login successful, redirecting to /billetera');
        
        // Redirigir a la página de billetera
        navigate('/billetera');
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (error) {
      setError('An error occurred');
      console.error('Request failed:', error);
    }
  };

  return (
    <Container component="main" maxWidth="xs">
      <Box className="formulario" sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5">
          Iniciar Sesión
        </Typography>
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
          <TextField
            margin="normal"
            required
            fullWidth
            label="Correo Electrónico"
            variant="outlined"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            label="Contraseña"
            type="password"
            variant="outlined"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {error && <Typography color="error">{error}</Typography>}
          {success && <Typography color="success">{success}</Typography>}
          <Button class="but"
            type="submit"
            variant="contained"
            color="primary"
            sx={{ mt: 2 }}
          >
            Iniciar Sesión
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default LoginForm;
