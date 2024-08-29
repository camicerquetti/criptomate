// src/components/UserList.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { List, ListItem, ListItemText, Typography } from '@mui/material';

const UserList = () => {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await axios.get('http://localhost:3001/api/users', {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
        });
        setUsers(response.data.users);
      } catch (err) {
        console.error('Error fetching users:', err);
      }
    };

    fetchUsers();
  }, []);

  return (
    <div>
      <Typography variant="h6">Lista de Usuarios</Typography>
      <List>
        {users.map(user => (
          <ListItem key={user.id}>
            <ListItemText primary={`ID: ${user.id}, Nombre: ${user.name}`} />
          </ListItem>
        ))}
      </List>
    </div>
  );
};

export default UserList;
