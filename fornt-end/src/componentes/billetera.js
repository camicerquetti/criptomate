import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Card,
  CardContent,
  Button,
  Box,
  Grid,
  TextField,
  CircularProgress,
  Snackbar,
  Alert,
  FormControlLabel,
  Checkbox
} from '@mui/material';
import monedaImage from '../Designer2.jpeg'; // Asegúrate de que la imagen esté en el directorio correcto

const Billetera = () => {
  const [balance, setBalance] = useState(0);
  const [senderId, setSenderId] = useState('');
  const [recipientId, setRecipientId] = useState('');
  const [amount, setAmount] = useState('');
  const [loading, setLoading] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('info');
  const navigate = useNavigate();

  const fetchBalance = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token) throw new Error('Token is missing');

      const response = await axios.get('http://localhost:3001/api/wallet', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      setBalance(parseFloat(response.data.balance) || 0);
    } catch (error) {
      console.error('Error fetching balance:', error);
      navigate('/login');
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    fetchBalance();
  }, [fetchBalance]);

  const showSnackbar = (message, severity) => {
    setSnackbarMessage(message);
    setSnackbarSeverity(severity);
    setSnackbarOpen(true);
  };

  const handleSnackbarClose = () => {
    setSnackbarOpen(false);
  };

  const isValidUserId = (id) => Number.isInteger(parseInt(id, 10)) && parseInt(id, 10) > 0;
  const isValidAmount = (amount) => !isNaN(amount) && amount > 0;

  const handleSendCoins = async () => {
    if (!isValidUserId(senderId) || !isValidUserId(recipientId) || !isValidAmount(amount)) {
      showSnackbar('Por favor, rellena todos los campos con valores válidos', 'warning');
      return;
    }

    const numericAmount = parseFloat(amount);
    const token = localStorage.getItem('token');
    if (!token) {
      showSnackbar('Token de autorización faltante', 'error');
      navigate('/login');
      return;
    }

    setLoading(true);
    try {
      const requestData = {
        fromUserId: parseInt(senderId, 10),
        toUserId: parseInt(recipientId, 10),
        amount: numericAmount,
        isAdmin: isAdmin
      };

      console.log('Sending coins with data:', requestData);

      const response = await axios.post('http://localhost:3001/api/enviodemonedas', requestData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      console.log('Response:', response.data);

      if (response.status === 200) {
        showSnackbar('Monedas enviadas exitosamente', 'success');
        await fetchBalance();
      } else {
        console.error('Error response:', response.data);
        showSnackbar(`Error al enviar monedas: ${response.data.error || response.statusText}`, 'error');
      }
    } catch (error) {
      console.error('Error al enviar monedas:', error.response ? error.response.data : error.message);
      showSnackbar(`Error al enviar monedas: ${error.response ? error.response.data.error : error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRequestCoins = async () => {
    if (!isValidUserId(recipientId) || !isValidAmount(amount)) {
      showSnackbar('Por favor, rellena todos los campos con valores válidos', 'warning');
      return;
    }

    const numericAmount = parseFloat(amount);
    const token = localStorage.getItem('token');
    if (!token) {
      showSnackbar('Token de autorización faltante', 'error');
      navigate('/login');
      return;
    }

    setLoading(true);
    try {
      const requestData = {
        toUserId: parseInt(recipientId, 10),
        amount: numericAmount,
        isAdmin: isAdmin
      };

      console.log('Requesting coins with data:', requestData);

      const response = await axios.post('http://localhost:3001/api/requestcoins', requestData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      console.log('Response:', response.data);

      if (response.status === 200) {
        showSnackbar('Solicitud de monedas realizada exitosamente', 'success');
      } else {
        console.error('Error response:', response.data);
        showSnackbar(`Error al solicitar monedas: ${response.data.error || response.statusText}`, 'error');
      }
    } catch (error) {
      console.error('Error al solicitar monedas:', error.response ? error.response.data : error.message);
      showSnackbar(`Error al solicitar monedas: ${error.response ? error.response.data.error : error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token'); // Elimina el token de almacenamiento local
    navigate('/login'); // Redirige al usuario a la página de inicio de sesión
  };

  const safeToFixed = (num, decimals = 2) => num.toFixed(decimals);

  return (
    <Container component="main" maxWidth="md" sx={{ mt: 4 }} >
      <Box display="flex" justifyContent="center" alignItems="center" mb={4}>
        <Typography variant="h4" sx={{ mr: 2 }}>
          Mi Billetera
        </Typography>
        <Button  class="but"
          variant="contained"
          sx={{ bgcolor: 'red', color: 'white', '&:hover': { bgcolor: 'darkred' } }}
          onClick={handleLogout}
        >
          Cerrar Sesión
        </Button>
      </Box>
      <Grid container spacing={3} justifyContent="center">
        <Grid item xs={12} sm={6} md={4}>
          <Card variant="outlined">
            <CardContent>
              <Box display="flex" flexDirection="column" alignItems="center">
                <img
                  src={monedaImage}
                  alt="Logo"
                  style={{ width: '50px', height: '50px', marginBottom: '16px' }}
                />
                <Typography variant="h5" component="div" gutterBottom>
                  Saldo Disponible:
                </Typography>
                <Typography variant="h6">
                  {loading ? <CircularProgress /> : `${safeToFixed(balance)} monedas`}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={4}>
          <Card variant="outlined">
            <CardContent>
              <Box display="flex" flexDirection="column" alignItems="center">
                <TextField
                  label="ID del Administrador (opcional)"
                  variant="outlined"
                  value={senderId}
                  onChange={(e) => setSenderId(e.target.value)}
                  sx={{ mb: 2 }}
                />
                <TextField
                  label="ID del destinatario"
                  variant="outlined"
                  value={recipientId}
                  onChange={(e) => setRecipientId(e.target.value)}
                  sx={{ mb: 2 }}
                />
                <TextField
                  label="Cantidad"
                  type="number"
                  variant="outlined"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  sx={{ mb: 2 }}
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
                  sx={{ mb: 2, bgcolor: 'black', color: 'white', '&:hover': { bgcolor: 'grey.800' } }}
                  onClick={handleSendCoins}
                  disabled={loading}
                >
                  Enviar Monedas
                </Button>
                <Button 
                  variant="contained"
                  sx={{ bgcolor: 'black', color: 'white', '&:hover': { bgcolor: 'grey.800' } }}
                  onClick={handleRequestCoins}
                >
                  Pedir Monedas
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
      <Snackbar open={snackbarOpen} autoHideDuration={6000} onClose={handleSnackbarClose}>
        <Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default Billetera;
