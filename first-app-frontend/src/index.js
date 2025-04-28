import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import Keycloak from 'keycloak-js';
import './index.css';

const keycloak = new Keycloak({
  url: 'https://keycloak.guven.uk',
  realm: 'guven_realm',
  clientId: 'first_app_frontend',
});

const container = document.getElementById('root');
const root = createRoot(container);

root.render(
  <ReactKeycloakProvider
    authClient={keycloak}
      initOptions={{
          onLoad: 'login-required',
          pkceMethod: 'S256',
          checkLoginIframe: false    // <-- iframe kontrolünü kapat
        }}
    LoadingComponent={<div>Loading...</div>}
  >
    <App />
  </ReactKeycloakProvider>
);