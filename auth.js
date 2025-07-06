// Configuration - Replace with your actual values
const config = {
    clientId: "48001125-599a-489d-8ead-ce1802cc93f8", // Replace with your Azure AD app client ID
    redirectUri: "https://claudeoutlook.netlify.app/", // Must match redirect URI in Azure AD app
    scope: "openid profile email offline_access", // offline_access is required for refresh token
    authority: "https://login.microsoftonline.com/common" // Use 'common' for multi-tenant or 'consumers' for personal accounts
};

// DOM elements
const loginButton = document.getElementById('loginButton');
const resultsDiv = document.getElementById('results');
const accessTokenEl = document.getElementById('accessToken');
const refreshTokenEl = document.getElementById('refreshToken');
const userInfoEl = document.getElementById('userInfo');

// Initialize the app when the page loads
document.addEventListener('DOMContentLoaded', init);

function init() {
    loginButton.addEventListener('click', startLogin);
    
    // Check if we're returning from a redirect with auth code
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    
    if (error) {
        console.error('Authentication error:', error, urlParams.get('error_description'));
        alert(`Error: ${error}\n${urlParams.get('error_description')}`);
        return;
    }
    
    if (code) {
        // We have an authorization code, now exchange it for tokens
        exchangeCodeForTokens(code);
    }
}

function startLogin() {
    // Create the authorization URL
    const authUrl = new URL(`${config.authority}/oauth2/v2.0/authorize`);
    
    authUrl.searchParams.append('client_id', config.clientId);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', config.redirectUri);
    authUrl.searchParams.append('response_mode', 'query');
    authUrl.searchParams.append('scope', config.scope);
    authUrl.searchParams.append('prompt', 'consent'); // Ensure consent is prompted to get refresh token
    
    // Redirect to Microsoft login
    window.location.href = authUrl.toString();
}

async function exchangeCodeForTokens(code) {
    try {
        // Create token endpoint URL
        const tokenUrl = `${config.authority}/oauth2/v2.0/token`;
        
        // Prepare the request body
        const body = new URLSearchParams();
        body.append('client_id', config.clientId);
        body.append('code', code);
        body.append('redirect_uri', config.redirectUri);
        body.append('grant_type', 'authorization_code');
        
        // Make the token request
        const response = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: body
        });
        
        if (!response.ok) {
            throw new Error(`Token request failed: ${response.status}`);
        }
        
        const tokens = await response.json();
        
        // Display the tokens
        displayResults(tokens);
        
        // Store tokens in session storage (for demo purposes only - not secure for production)
        sessionStorage.setItem('msal_tokens', JSON.stringify(tokens));
        
        // Clean the URL
        window.history.replaceState({}, document.title, window.location.pathname);
        
    } catch (error) {
        console.error('Token exchange error:', error);
        alert('Failed to exchange code for tokens. See console for details.');
    }
}

function displayResults(tokens) {
    // Show the results section
    resultsDiv.classList.remove('hidden');
    
    // Display the access token (truncated for security)
    accessTokenEl.textContent = tokens.access_token 
        ? `${tokens.access_token.substring(0, 30)}...` 
        : 'No access token received';
    
    // Display the refresh token (truncated for security)
    refreshTokenEl.textContent = tokens.refresh_token 
        ? `${tokens.refresh_token.substring(0, 30)}...` 
        : 'No refresh token received';
    
    // Get and display user info if we have an access token
    if (tokens.access_token) {
        getUserInfo(tokens.access_token);
    }
}

async function getUserInfo(accessToken) {
    try {
        const response = await fetch('https://graph.microsoft.com/oidc/userinfo', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`User info request failed: ${response.status}`);
        }
        
        const userInfo = await response.json();
        userInfoEl.textContent = JSON.stringify(userInfo, null, 2);
    } catch (error) {
        console.error('User info error:', error);
        userInfoEl.textContent = 'Failed to fetch user info';
    }
}
