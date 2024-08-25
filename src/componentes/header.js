// src/components/Header.js
import React from 'react';
import { AppBar, Toolbar, Typography, Button, IconButton } from '@mui/material';
import { Link } from 'react-router-dom'; // Importa Link para la navegación
import logo from "../moneda.jpeg";
import '../App.css';

const Header = () => (
  <AppBar class="menu" position="static">
    <Toolbar>
      <IconButton component={Link} to="/" edge="start" color="inherit" aria-label="home">
        <img
          src={logo}
          alt="Logo"
          className="logo" // Usa la clase CSS para el logo
        />
      </IconButton>
      <Typography color="white" variant="h6" component="div" sx={{ flexGrow: 1 }}>
        CriptoMate
      </Typography>
      <Button
        component={Link}
        to="/login"
        sx={{
          mr: 2,
          color: 'white', // Color del texto del botón
          bgcolor: 'transparent', // Fondo transparente del botón
          border: '1px solid white', // Opcional: Borde blanco
          '&:hover': {
            bgcolor: 'rgba(255, 255, 255, 0.2)', // Fondo al pasar el ratón
          },
        }}
      >
        Login
      </Button>
      <Button
        component={Link}
        to="/register"
        sx={{
          mr: 2,
          color: 'white', // Color del texto del botón
          bgcolor: 'transparent', // Fondo transparente del botón
          border: '1px solid white', // Opcional: Borde blanco
          '&:hover': {
            bgcolor: 'rgba(255, 255, 255, 0.2)', // Fondo al pasar el ratón
          },
        }}
      >
        Sign Up
      </Button>
    </Toolbar>
  </AppBar>
);

export default Header;

