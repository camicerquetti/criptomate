import React from 'react';
import { Box, Typography, Button, Card, CardContent, CardMedia, Dialog, DialogTitle, DialogContent, DialogActions, DialogContentText } from '@mui/material';
import { useNavigate } from 'react-router-dom'; // Importa useNavigate
import backgroundImage from '../Designer1.jpeg'; // Cambia la ruta según donde hayas colocado tu imagen
import Image1 from '../propaganda2.jpeg'; // Cambia la ruta según donde hayas colocado tu imagen
import Image2 from '../monedas2.jpeg'; // Cambia la ruta según donde hayas colocado tu imagen
import '../App.css';

const Main = () => {
  const [openDialog, setOpenDialog] = React.useState(false); // Estado para controlar el diálogo
  const navigate = useNavigate(); // Inicializa useNavigate

  const handleOpenDialog = () => {
    setOpenDialog(true); // Abre el diálogo
  };

  const handleCloseDialog = () => {
    setOpenDialog(false); // Cierra el diálogo
  };

  const handleNavigateToRegister = () => {
    navigate('/register'); // Redirige a la página de registro
  };

  return (
    <Box
      sx={{
        backgroundImage: `url(${backgroundImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        height: '100vh', // Ocupa toda la altura de la ventana
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        color: 'white',
        padding: 2,
      }}
    >
      <Typography class="text" variant="h1">Bienvenido a CriptoMate</Typography>
      
      <Box sx={{ display: 'flex', gap: 2, marginTop: 4, width: '100%', maxWidth: 900 }}>
        {/* Tarjeta 1 */}
        <Box sx={{ flex: 1, display: 'flex' }}>
          <Card sx={{ flex: 1 }}>
            <CardMedia
              component="img"
              height="140"
              image={Image1}
              alt="Imagen 1"
            />
            <CardContent>
              <Typography variant="h5">Tené una cuenta gratis</Typography>
              <Typography variant="body2">
                100% digital, la abrís en minutos y podés manejar las finanzas de tus clases como quieras.
              </Typography>
              <Button class="but" variant="contained" sx={{ marginTop: 2 }} onClick={handleOpenDialog}>
                Registrate
              </Button>
            </CardContent>
          </Card>
        </Box>

        {/* Tarjeta 2 */}
        <Box sx={{ flex: 1, display: 'flex' }}>
          <Card sx={{ flex: 1 }}>
            <CardMedia
              component="img"
              height="140"
              image={Image2}
              alt="Imagen 2"
            />
            <CardContent>
              <Typography variant="h5">Gana y tené tus monedas al instante</Typography>
              <Typography variant="body2">
                Cambia tus monedas y obtene los mejores beneficios de tu clase.
              </Typography>
              <Button class="but" variant="contained" sx={{ marginTop: 2 }} onClick={handleNavigateToRegister}>
                Comenzar ahora
              </Button>
            </CardContent>
          </Card>
        </Box>
      </Box>

      {/* Diálogo para descargar la app */}
      <Dialog open={openDialog} onClose={handleCloseDialog} fullWidth maxWidth="sm">
        <DialogTitle>¡Descarga nuestra App!</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Para disfrutar de todas nuestras funcionalidades, descarga nuestra aplicación móvil.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cerrar</Button>
          <Button onClick={() => window.open('https://linktotheapp.com', '_blank')} color="primary">
            Descargar App
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Main;
