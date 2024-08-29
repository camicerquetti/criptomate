// src/componentes/PoliticasDePrivacidad.js
import React from 'react';
import { Box, Typography, Container } from '@mui/material';

const PoliticasDePrivacidad = () => {
  return (
    <Container>
      <Box sx={{ padding: 2 }}>
        <Typography variant="h4" gutterBottom>
          Políticas de Privacidad
        </Typography>
        <Typography variant="h6" gutterBottom>
          1. Información que Recopilamos
        </Typography>
        <Typography paragraph>
          Recopilamos información personal que usted nos proporciona directamente cuando se registra en nuestra aplicación, como su nombre, dirección de correo electrónico y cualquier otra información que decida compartir. También podemos recopilar información sobre el uso de nuestra aplicación mediante el uso de cookies y tecnologías similares.
        </Typography>
        <Typography variant="h6" gutterBottom>
          2. Uso de la Información
        </Typography>
        <Typography paragraph>
          Utilizamos la información recopilada para proporcionar, mantener y mejorar nuestros servicios, así como para personalizar su experiencia en la aplicación. También podemos usar su información para comunicarnos con usted, por ejemplo, para enviarle actualizaciones y notificaciones.
        </Typography>
        <Typography variant="h6" gutterBottom>
          3. Compartición de Información
        </Typography>
        <Typography paragraph>
          No compartimos su información personal con terceros, excepto en los casos en que sea necesario para cumplir con las leyes, regulaciones, o procesos legales. También podemos compartir su información con proveedores de servicios que nos ayudan a operar nuestra aplicación, siempre que estos proveedores se comprometan a proteger su información de manera adecuada.
        </Typography>
        <Typography variant="h6" gutterBottom>
          4. Seguridad
        </Typography>
        <Typography paragraph>
          Implementamos medidas de seguridad razonables para proteger su información personal contra el acceso no autorizado, la alteración, la divulgación o la destrucción. Sin embargo, ninguna transmisión de datos por Internet o sistema de almacenamiento de datos es 100% seguro, por lo que no podemos garantizar la seguridad absoluta.
        </Typography>
        <Typography variant="h6" gutterBottom>
          5. Derechos del Usuario
        </Typography>
        <Typography paragraph>
          Usted tiene el derecho de acceder, corregir o eliminar su información personal. Puede solicitar estos cambios poniéndose en contacto con nosotros a través de los medios proporcionados en esta política.
        </Typography>
        <Typography variant="h6" gutterBottom>
          6. Cambios en la Política de Privacidad
        </Typography>
        <Typography paragraph>
          Podemos actualizar nuestra Política de Privacidad de vez en cuando. Le notificaremos sobre cualquier cambio publicando la nueva política en esta página. Le recomendamos que revise esta Política de Privacidad periódicamente para estar informado sobre cómo protegemos su información.
        </Typography>
        <Typography variant="h6" gutterBottom>
          7. Contacto
        </Typography>
        <Typography paragraph>
          Si tiene alguna pregunta sobre esta Política de Privacidad, por favor contáctenos en [su dirección de correo electrónico de contacto].
        </Typography>
      </Box>
    </Container>
  );
};

export default PoliticasDePrivacidad;
