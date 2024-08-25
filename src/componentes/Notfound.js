// src/components/NotFound.js
import React from 'react';
import { Typography, Box } from '@mui/material';

const NotFound = () => {
  return (
    <Box p={2}>
      <Typography variant="h4" color="error" align="center">
        404 - Página No Encontrada
      </Typography>
    </Box>
  );
};

export default NotFound;
