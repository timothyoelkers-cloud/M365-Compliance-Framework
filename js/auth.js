/* ═══════════════════════════════════════════
   TENANT AUTH — MSAL.js 2.x browser authentication
═══════════════════════════════════════════ */
const TenantAuth = (() => {
  let msalInstance = null;
  let currentAccount = null;

  const GRAPH_SCOPES = [
    'User.Read',
    'Policy.ReadWrite.ConditionalAccess',
    'DeviceManagementManagedDevices.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'Policy.ReadWrite.Authorization',
    'Directory.ReadWrite.All',
    'Policy.ReadWrite.AuthenticationMethod',
  ];

  const CLIENT_ID_KEY = 'm365-compliance-clientId';

  // ─── Initialization ───
  async function init(clientId, redirectUri) {
    if (!window.msal) {
      console.error('MSAL.js not loaded');
      return false;
    }
    const config = {
      auth: {
        clientId: clientId,
        authority: 'https://login.microsoftonline.com/common',
        redirectUri: redirectUri || window.location.origin + window.location.pathname,
      },
      cache: {
        cacheLocation: 'localStorage',
        storeAuthStateInCookie: true,
      },
    };
    msalInstance = new msal.PublicClientApplication(config);
    await msalInstance.initialize();
    return true;
  }

  async function handleRedirectPromise() {
    if (!msalInstance) return null;
    try {
      const response = await msalInstance.handleRedirectPromise();
      if (response && response.account) {
        currentAccount = response.account;
        msalInstance.setActiveAccount(currentAccount);
        updateAuthState();
      } else {
        // Check for already logged-in accounts
        const accounts = msalInstance.getAllAccounts();
        if (accounts.length > 0) {
          currentAccount = accounts[0];
          msalInstance.setActiveAccount(currentAccount);
          updateAuthState();
        }
      }
      return response;
    } catch (err) {
      console.error('MSAL redirect error:', err);
      return null;
    }
  }

  // ─── Login / Logout ───
  async function login() {
    if (!msalInstance) return;
    try {
      await msalInstance.loginRedirect({ scopes: GRAPH_SCOPES });
    } catch (err) {
      console.error('Login failed:', err);
      if (typeof showToast === 'function') showToast('Login failed: ' + err.message);
    }
  }

  async function logout() {
    if (!msalInstance) return;
    currentAccount = null;
    updateAuthState();
    try {
      await msalInstance.logoutRedirect({
        postLogoutRedirectUri: window.location.origin + window.location.pathname,
      });
    } catch (err) {
      console.error('Logout error:', err);
    }
  }

  // ─── Token Acquisition ───
  async function getAccessToken(scopes) {
    if (!msalInstance || !currentAccount) return null;
    try {
      const response = await msalInstance.acquireTokenSilent({
        scopes: scopes || GRAPH_SCOPES,
        account: currentAccount,
      });
      return response.accessToken;
    } catch (err) {
      if (err instanceof msal.InteractionRequiredAuthError) {
        try {
          await msalInstance.acquireTokenRedirect({
            scopes: scopes || GRAPH_SCOPES,
          });
        } catch (redirectErr) {
          console.error('Token redirect failed:', redirectErr);
        }
      } else {
        console.error('Token acquisition failed:', err);
      }
      return null;
    }
  }

  async function getGraphToken() {
    return getAccessToken(GRAPH_SCOPES);
  }

  // ─── Auth State ───
  function isAuthenticated() {
    return currentAccount !== null;
  }

  function getAccount() {
    if (!currentAccount) return null;
    return {
      name: currentAccount.name || '',
      email: currentAccount.username || '',
      tenantId: currentAccount.tenantId || '',
      homeAccountId: currentAccount.homeAccountId || '',
    };
  }

  function updateAuthState() {
    if (typeof AppState !== 'undefined') {
      AppState.set('authIsConnected', currentAccount !== null);
      AppState.set('authAccount', getAccount());
      AppState.set('authTenantId', currentAccount ? currentAccount.tenantId : null);
    }
  }

  // ─── Client ID Storage ───
  function getStoredClientId() {
    try { return localStorage.getItem(CLIENT_ID_KEY) || ''; }
    catch (e) { return ''; }
  }

  function setStoredClientId(clientId) {
    try { localStorage.setItem(CLIENT_ID_KEY, clientId); }
    catch (e) { /* storage unavailable */ }
  }

  return {
    init, handleRedirectPromise,
    login, logout,
    getAccessToken, getGraphToken,
    isAuthenticated, getAccount, updateAuthState,
    getStoredClientId, setStoredClientId,
    GRAPH_SCOPES,
  };
})();
