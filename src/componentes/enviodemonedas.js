import React, { useState } from 'react';
import axios from 'axios';
import { Button, TextField, Box, Typography, FormControlLabel, Checkbox } from '@mui/material';

const SendCoins = () => {
  const [fromUserId, setFromUserId] = useState('');
  const [toUserId, setToUserId] = useState('');
  const [amount, setAmount] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const handleSendCoins = async () => {
    // Validación de campos
    if (!fromUserId || !toUserId || !amount || isNaN(amount) || parseFloat(amount) <= 0) {
      setError('Por favor, rellena todos los campos con valores válidos.');
      setMessage('');
      return;
    }
  
    // Validación de token
    const token = localStorage.getItem('token');
    if (!token) {
      setError('No estás autenticado. Por favor, inicia sesión.');
      setMessage('');
      return;
    }
  
    try {
      const response = await axios.post('http://localhost:3001/api/enviodemonedas', {
        fromUserId: parseInt(fromUserId, 10),
        toUserId: parseInt(toUserId, 10),
        amount: parseFloat(amount),
        isAdmin: isAdmin // Asegúrate de enviar este campo si el backend lo requiere
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
      });
  
      setMessage(response.data.message);
      setError('');
      
      // Restablecer campos después del éxito
      setFromUserId('');
      setToUserId('');
      setAmount('');
      setIsAdmin(false);
    } catch (err) {
      console.error(err); // Para depuración
      setError(err.response?.data?.error || 'Ha ocurrido un error');
      setMessage('');
    }
  };
  
  return (
    <Box p={2}>
      <Typography variant="h5">Enviar Monedas</Typography>
      <TextField
        label="ID del Usuario Enviador"
        variant="outlined"
        fullWidth
        margin="normal"
        value={fromUserId}
        onChange={(e) => setFromUserId(e.target.value)}
      />
      <TextField
        label="ID del Usuario Receptor"
        variant="outlined"
        fullWidth
        margin="normal"
        value={toUserId}
        onChange={(e) => setToUserId(e.target.value)}
      />
      <TextField
        label="Cantidad"
        variant="outlined"
        type="number"
        fullWidth
        margin="normal"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
      />
      <FormControlLabel
        control={
          <Checkbox
            checked={isAdmin}
            onChange={(e) => setIsAdmin(e.target.checked)}
          />
        }
        label="Enviar como Administrador"
      />
      <Button
        variant="contained"
        color="primary"
        onClick={handleSendCoins}
        style={{ marginTop: '16px' }}
      >
        Enviar
      </Button>
      {error && <Typography color="error">{error}</Typography>}
      {message && <Typography color="primary">{message}</Typography>}
    </Box>
  );
};

export default SendCoins;
