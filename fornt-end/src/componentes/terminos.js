// src/componentes/TerminosYCondiciones.js
import React from 'react';
import { Box, Typography, Container } from '@mui/material';

const TerminosYCondiciones = () => {
  return (
    <Container>
      <Box sx={{ padding: 2 }}>
        <Typography variant="h4" gutterBottom>
          Términos y Condiciones
        </Typography>
        <Typography variant="h6" gutterBottom>
          1. Aceptación de los Términos
        </Typography>
        <Typography paragraph>
          Al acceder y utilizar la aplicación CriptoMate ("nosotros", "nuestro" o "nosotros"), usted acepta cumplir y estar sujeto a estos Términos y Condiciones ("Términos"). Si no está de acuerdo con estos Términos, no utilice nuestra aplicación.
        </Typography>
        <Typography variant="h6" gutterBottom>
          2. Uso de la Aplicación
        </Typography>
        <Typography paragraph>
          <strong>2.1</strong> Usted debe utilizar nuestra aplicación de acuerdo con todas las leyes y regulaciones locales, nacionales e internacionales aplicables.
        </Typography>
        <Typography paragraph>
          <strong>2.2</strong> Está prohibido usar la aplicación para cualquier propósito ilegal o no autorizado. Usted acepta no participar en ninguna actividad que interfiera o interrumpa la aplicación o los servidores y redes conectados a la misma.
        </Typography>
        <Typography variant="h6" gutterBottom>
          3. Propiedad Intelectual
        </Typography>
        <Typography paragraph>
          <strong>3.1</strong> Todo el contenido de la aplicación, incluyendo pero no limitado a texto, gráficos, logotipos, iconos, imágenes y software, es propiedad de CriptoMate o de sus proveedores de contenido y está protegido por leyes de propiedad intelectual.
        </Typography>
        <Typography paragraph>
          <strong>3.2</strong> Usted no puede reproducir, distribuir, modificar, mostrar, realizar, transmitir, publicar o crear trabajos derivados basados en cualquier contenido de la aplicación sin el consentimiento previo por escrito de CriptoMate.
        </Typography>
        <Typography variant="h6" gutterBottom>
          4. Registro y Cuentas
        </Typography>
        <Typography paragraph>
          <strong>4.1</strong> Para acceder a ciertas funcionalidades de la aplicación, es posible que deba registrarse y crear una cuenta. Usted acepta proporcionar información precisa y completa durante el proceso de registro.
        </Typography>
        <Typography paragraph>
          <strong>4.2</strong> Usted es responsable de mantener la confidencialidad de su cuenta y contraseña, y acepta notificar a CriptoMate de inmediato cualquier uso no autorizado de su cuenta.
        </Typography>
        <Typography paragraph>
          <strong>4.3</strong> CriptoMate se reserva el derecho de cerrar su cuenta si se sospecha de actividad fraudulenta o de incumplimiento de estos Términos.
        </Typography>
        <Typography variant="h6" gutterBottom>
          5. Responsabilidad
        </Typography>
        <Typography paragraph>
          <strong>5.1</strong> La aplicación y el contenido se proporcionan "tal cual" y "según disponibilidad". CriptoMate no garantiza que la aplicación esté libre de errores, virus o interrupciones.
        </Typography>
        <Typography paragraph>
          <strong>5.2</strong> CriptoMate no será responsable de ningún daño indirecto, incidental, especial o consecuente que resulte del uso o la imposibilidad de uso de la aplicación.
        </Typography>
        <Typography variant="h6" gutterBottom>
          6. Enlaces a Sitios de Terceros
        </Typography>
        <Typography paragraph>
          <strong>6.1</strong> Nuestra aplicación puede contener enlaces a sitios web de terceros. Estos enlaces se proporcionan para su conveniencia. No controlamos estos sitios web y no somos responsables de su contenido o de cualquier pérdida o daño que pueda surgir del uso de dichos sitios.
        </Typography>
        <Typography paragraph>
          <strong>6.2</strong> Su acceso a estos sitios web de terceros está sujeto a sus propios términos y condiciones.
        </Typography>
        <Typography variant="h6" gutterBottom>
          7. Modificaciones
        </Typography>
        <Typography paragraph>
          <strong>7.1</strong> CriptoMate se reserva el derecho de modificar estos Términos en cualquier momento. Las modificaciones serán efectivas cuando se publiquen en la aplicación.
        </Typography>
        <Typography paragraph>
          <strong>7.2</strong> Su uso continuo de la aplicación después de cualquier cambio en los Términos constituye su aceptación de dichos cambios.
        </Typography>
        <Typography variant="h6" gutterBottom>
          8. Terminación
        </Typography>
        <Typography paragraph>
          <strong>8.1</strong> CriptoMate se reserva el derecho de suspender o terminar su acceso a la aplicación en cualquier momento, sin previo aviso, por cualquier motivo, incluyendo pero no limitado a la violación de estos Términos.
        </Typography>
        <Typography variant="h6" gutterBottom>
          9. Ley Aplicable y Jurisdicción
        </Typography>
        <Typography paragraph>
          <strong>9.1</strong> Estos Términos se regirán e interpretarán de acuerdo con las leyes de la República Argentina, sin tener en cuenta sus principios de conflicto de leyes.
        </Typography>
        <Typography paragraph>
          <strong>9.2</strong> Cualquier disputa que surja en relación con estos Términos será resuelta en los tribunales competentes de la Ciudad Autónoma de Buenos Aires, Argentina.
        </Typography>
        <Typography variant="h6" gutterBottom>
          10. Internacionalidad
        </Typography>
        <Typography paragraph>
          <strong>10.1</strong> Si usted utiliza nuestra aplicación desde fuera de Argentina, es responsable de cumplir con las leyes locales aplicables. El acceso a la aplicación desde territorios donde su contenido es ilegal está prohibido.
        </Typography>
        <Typography variant="h6" gutterBottom>
          11. Contacto
        </Typography>
        <Typography paragraph>
          Si tiene alguna pregunta sobre estos Términos, por favor contáctenos.
        </Typography>
      </Box>
    </Container>
  );
};

export default TerminosYCondiciones;
