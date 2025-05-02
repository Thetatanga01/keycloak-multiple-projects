import React, { useState } from 'react';
import { useKeycloak } from '@react-keycloak/web';
import './App.css';

function App() {
  const { keycloak, initialized } = useKeycloak();
  const [apiResponse, setApiResponse] = useState('');

  // API URL'leri için ortam değişkenlerini kullan
  const FIRST_BACKEND_URL = process.env.REACT_APP_FIRST_BACKEND_URL || 'http://localhost:8080';
  const SECOND_BACKEND_URL = process.env.REACT_APP_SECOND_BACKEND_URL || 'http://localhost:9090';
  const FIRST_FRONTEND_URL = process.env.REACT_APP_FIRST_FRONTEND_URL || 'http://localhost:3000';
  const SECOND_FRONTEND_URL = process.env.REACT_APP_SECOND_FRONTEND_URL || 'http://localhost:4000';

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
      <h1>SECOND APP FRONTEND</h1>
      <div className="button-group">
        <button
          className="btn btn-primary"
          onClick={() => callApi(`${SECOND_BACKEND_URL}/api/user`)}
        >
          Second App Backend Api Call
        </button>
        <button
          className="btn btn-primary"
          onClick={() => callApi(`${FIRST_BACKEND_URL}/api/user`)}
        >
          First App Backend Api Call
        </button>
        <button
          className="btn btn-secondary"
          onClick={() => window.location.href = `${SECOND_BACKEND_URL}/api/user?continue`}
        >
          Second App Backend EndPoint
        </button>
        <button
          className="btn btn-secondary"
          onClick={() => window.location.href = `${FIRST_FRONTEND_URL}`}
        >
          First App FrontEnd EndPoint
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