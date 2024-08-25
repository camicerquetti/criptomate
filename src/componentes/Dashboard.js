// src/components/Dashboard.js
import React from 'react';
import { Grid, Paper, Typography } from '@mui/material';
import SendCoins from './enviodemonedas'; // Asegúrate de tener este componente
import UserList from './UserList'; // Asegúrate de tener este componente

const Dashboard = () => {
  return (
    <div>
      <Typography variant="h4" gutterBottom align="center">
        Panel de Control
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} style={{ padding: '16px' }}>
            <Typography variant="h6" gutterBottom>
              Enviar Monedas
            </Typography>
            <SendCoins />
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} style={{ padding: '16px' }}>
            <Typography variant="h6" gutterBottom>
              Lista de Usuarios
            </Typography>
            <UserList />
          </Paper>
        </Grid>
      </Grid>
    </div>
  );
};

export default Dashboard;
