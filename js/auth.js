/* ═══════════════════════════════════════════
   TENANT AUTH — MSAL.js 2.x browser authentication
   App Registration: "Framework-Assessment-Deployment"
═══════════════════════════════════════════ */
const TenantAuth = (() => {
  let msalInstance = null;
  let currentAccount = null;

  // ─── App Registration: Framework-Assessment-Deployment ───
  const CLIENT_ID = 'c9bcd329-2658-493b-ab75-6afc6d98adc4';
  const REDIRECT_URI = window.location.origin + window.location.pathname;

  // Individual scopes (shown on consent screen)
  const GRAPH_SCOPES = [
    'User.Read',
    'Policy.ReadWrite.ConditionalAccess',
    'DeviceManagementManagedDevices.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'Policy.ReadWrite.Authorization',
    'Directory.ReadWrite.All',
    'Policy.ReadWrite.AuthenticationMethod',
  ];

  // .default scope — returns ALL admin-consented permissions in the token
  const TOKEN_SCOPES = ['https://graph.microsoft.com/.default'];

  // ─── Initialization ───
  async function init() {
    if (msalInstance) return true;
    if (!window.msal) {
      console.error('MSAL.js not loaded');
      return false;
    }
    const config = {
      auth: {
        clientId: CLIENT_ID,
        authority: 'https://login.microsoftonline.com/common',
        redirectUri: REDIRECT_URI,
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
    if (!msalInstance) await init();
    try {
      const response = await msalInstance.loginPopup({
        scopes: GRAPH_SCOPES,
        prompt: 'consent',
      });
      if (response && response.account) {
        currentAccount = response.account;
        msalInstance.setActiveAccount(currentAccount);
        updateAuthState();
      }
      return response;
    } catch (err) {
      console.error('Login failed:', err);
      if (typeof showToast === 'function') showToast('Login failed: ' + err.message);
      return null;
    }
  }

  async function logout() {
    if (!msalInstance) return;
    currentAccount = null;
    updateAuthState();
    // Force-clear all MSAL cached tokens from localStorage
    Object.keys(localStorage).forEach(key => {
      if (key.indexOf('msal') !== -1 || key.indexOf('login.windows.net') !== -1) {
        localStorage.removeItem(key);
      }
    });
    try {
      await msalInstance.logoutPopup({
        postLogoutRedirectUri: REDIRECT_URI,
      });
    } catch (err) {
      console.error('Logout error:', err);
    }
    // Re-initialize MSAL with a clean instance
    msalInstance = null;
    await init();
  }

  // ─── Token Acquisition ───
  async function getAccessToken() {
    if (!msalInstance || !currentAccount) return null;
    try {
      const response = await msalInstance.acquireTokenSilent({
        scopes: TOKEN_SCOPES,
        account: currentAccount,
        forceRefresh: true,
      });
      return response.accessToken;
    } catch (err) {
      if (err instanceof msal.InteractionRequiredAuthError) {
        try {
          const response = await msalInstance.acquireTokenPopup({
            scopes: TOKEN_SCOPES,
            prompt: 'consent',
          });
          if (response && response.account) {
            currentAccount = response.account;
            msalInstance.setActiveAccount(currentAccount);
          }
          return response.accessToken;
        } catch (popupErr) {
          console.error('Token popup failed:', popupErr);
        }
      } else {
        console.error('Token acquisition failed:', err);
      }
      return null;
    }
  }

  async function getGraphToken() {
    return getAccessToken();
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

  return {
    init, handleRedirectPromise,
    login, logout,
    getAccessToken, getGraphToken,
    isAuthenticated, getAccount, updateAuthState,
    GRAPH_SCOPES,
  };
})();
