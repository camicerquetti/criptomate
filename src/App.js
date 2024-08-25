import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Header from './componentes/header'; 
import Main from './componentes/main'; 
import Footer from './componentes/footer'; 
import Nosotros from './componentes/nosotros'; 
import Terminos from './componentes/terminos'; 
import Politicas from './componentes/politicas'; 
import Contacto from './componentes/contacto';
import Login from './componentes/login'; 
import Register from './componentes/register'; 
import Billetera from './componentes/billetera'; 
import Dashboard from './componentes/Dashboard';
import NotFound from './componentes/Notfound';
import UserList from './componentes/UserList';
import Enviodemonedas from './componentes/enviodemonedas';
function App() {
  const [data, setData] = useState(null); // Estado para almacenar datos del backend
  const [loading, setLoading] = useState(true); // Estado para gestionar la carga de datos
  const [error, setError] = useState(null); // Estado para gestionar errores

  useEffect(() => {
    // Función para realizar la solicitud fetch
    const fetchData = async () => {
      try {
        const response = await fetch('http://localhost:3001/api/endpoint');

        if (!response.ok) {
          throw new Error('Network response was not ok ' + response.statusText);
        }

        // Verifica el tipo de contenido antes de convertirlo a JSON
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          const result = await response.json();
          setData(result);
        } else {
          throw new Error('Expected JSON response');
        }
      } catch (error) {
        console.error('Error fetching data:', error);
        setError(error);
      } finally {
        setLoading(false);
      }
    };

    fetchData(); // Llama a la función para realizar la solicitud
  }, []); // El array vacío asegura que esto solo se ejecute una vez cuando el componente se monta

  return (
    <Router>
      <div className="App" style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <Header />
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Main />} />
            <Route path="/nosotros" element={<Nosotros />} />
            <Route path="/terminos" element={<Terminos />} />
            <Route path="/politicas" element={<Politicas />} />
            <Route path="/contacto" element={<Contacto />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/billetera" element={<Billetera />} />
            <Route path="/Dashboard" element={<Dashboard />} />
          <Route path="/enviodemonedas" element={<Enviodemonedas />} />
          <Route path="/UserList" element={<UserList />} />
          <Route path="/Notfound" element={<NotFound />} /> 
          </Routes>
          <div>
            <h1>Data from Backend:</h1>
            {loading && <p>Loading...</p>}
            {error && <p>Error: {error.message}</p>}
            {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
          </div>
        </main>
        <Footer />
      </div>
    </Router>
  );
}

export default App;
