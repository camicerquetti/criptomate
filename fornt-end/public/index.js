// src/index.js

import React from 'react';
import ReactDOM from 'react-dom';
import App from './App';
import './index.css'; // Verifica que los estilos globales se apliquen correctamente

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);
