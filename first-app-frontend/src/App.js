import React, { useState } from 'react';
import { useKeycloak } from '@react-keycloak/web';
import './App.css';

function App() {
  const { keycloak, initialized } = useKeycloak();
  const [apiResponse, setApiResponse] = useState('');

  if (!initialized) {
    return <div>Loading…</div>;
  }

  if (!keycloak.authenticated) {
    return (
      <div className="App-container">
        <button className="btn btn-primary" onClick={() => keycloak.login()}>
          Login
        </button>
      </div>
    );
  }

  const callApi = async (url) => {
    try {
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${keycloak.token}` },
      });
      const data = await response.text();
      setApiResponse(`Response from ${url}: ${data}`);
    } catch (error) {
      console.error('API çağrısı hatası:', error);
      setApiResponse(`Error calling ${url}`);
    }
  };

  return (
    <div className="App-container">
      <h1>FIRST APP FRONTEND</h1>
      <div className="button-group">
        <button
          className="btn btn-primary"
          onClick={() => callApi('http://localhost:8080/api/user')}
        >
          First App Backend Api Call
        </button>
        <button
          className="btn btn-primary"
          onClick={() => callApi('http://localhost:9090/api/user')}
        >
          Second App Backend Api Call
        </button>
        <button
          className="btn btn-secondary"
          onClick={() => window.location.href = 'http://localhost:9090/api/user?continue'}
        >
          Second App Backend EndPoint
        </button>
        <button
          className="btn btn-secondary"
          onClick={() => window.location.href = 'http://localhost:4000'}
        >
          Second App FrontEnd EndPoint
        </button>
        <button
          className="btn btn-logout"
          onClick={() => keycloak.logout()}
        >
          Logout
        </button>
      </div>
      {apiResponse && <div className="response-box">{apiResponse}</div>}
    </div>
  );
}

export default App;