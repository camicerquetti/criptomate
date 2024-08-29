import React, { useState } from 'react';
import { Box, TextField, Button, Typography, Container, FormControl, InputLabel, InputAdornment, IconButton, Input } from '@mui/material';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import axios from 'axios'; // Importa axios

const RegisterForm = () => {
  const [formValues, setFormValues] = useState({
    username: '',
    email: '',
    password: '',
  });

  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [successMessage, setSuccessMessage] = useState('');

  const handleChange = (e) => {
    setFormValues({
      ...formValues,
      [e.target.name]: e.target.value,
    });
  };

  const handleClickShowPassword = () => setShowPassword(!showPassword);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validaciones
    const newErrors = {};
    if (!formValues.username) newErrors.username = 'Username is required';
    if (!formValues.email) newErrors.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(formValues.email)) newErrors.email = 'Email is invalid'; // Basic email validation
    if (!formValues.password) newErrors.password = 'Password is required';
    else if (formValues.password.length < 8) newErrors.password = 'Password must be at least 8 characters long'; // Password length validation

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    try {
      // Enviar los datos al backend
      await axios.post('http://localhost:3001/api/register', formValues);

      // Manejar respuesta exitosa
      setSuccessMessage('User registered successfully!');
      setErrors({});
      setFormValues({
        username: '',
        email: '',
        password: '',
      });
    } catch (error) {
      // Manejar errores
      if (error.response && error.response.data) {
        setErrors({ server: error.response.data.error || 'An unexpected error occurred' });
      } else {
        setErrors({ server: 'An unexpected error occurred' });
      }
    }
  };

  return (
    <Container component="main" maxWidth="xs" sx={{ display: 'flex', flexDirection: 'column', flex: 1, paddingBottom: 4 }}>
      <Box
        sx={{
          marginTop: 8,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          padding: 3,
          borderRadius: 2,
          boxShadow: 3,
          backgroundColor: 'background.paper',
          flex: 1, // Allow the Box to grow and fill available space
        }}
      >
        <Typography component="h1" variant="h5">
          Register
        </Typography>
        <Box component="form" noValidate sx={{ mt: 1 }} onSubmit={handleSubmit}>
          <TextField
            margin="normal"
            required
            fullWidth
            id="username"
            label="Username"
            name="username"
            value={formValues.username}
            onChange={handleChange}
            error={!!errors.username}
            helperText={errors.username}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            id="email"
            label="Email Address"
            name="email"
            value={formValues.email}
            onChange={handleChange}
            error={!!errors.email}
            helperText={errors.email}
          />
          <FormControl margin="normal" required fullWidth variant="outlined">
            <InputLabel htmlFor="password">Password</InputLabel>
            <Input
              id="password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              value={formValues.password}
              onChange={handleChange}
              error={!!errors.password}
              endAdornment={
                <InputAdornment position="end">
                  <IconButton
                    edge="end"
                    onClick={handleClickShowPassword}
                    aria-label="toggle password visibility"
                  >
                    {showPassword ? <Visibility /> : <VisibilityOff />}
                  </IconButton>
                </InputAdornment>
              }
              label="Password"
            />
            {errors.password && (
              <Typography color="error" variant="caption" sx={{ mt: 1 }}>
                {errors.password}
              </Typography>
            )}
          </FormControl>
          {errors.server && (
            <Typography color="error" variant="caption" sx={{ mt: 1 }}>
              {errors.server}
            </Typography>
          )}
          {successMessage && (
            <Typography color="success" variant="caption" sx={{ mt: 1 }}>
              {successMessage}
            </Typography>
          )}
          <Button class="but"
            type="submit"
            fullWidth
            variant="contained"
            color="primary"
            sx={{ mt: 3, mb: 2 }}
          >
            Register
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default RegisterForm;
