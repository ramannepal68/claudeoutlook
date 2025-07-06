// netlify/functions/auth-start.js
// This function initiates the Microsoft OAuth flow
exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers };
  }

  try {
    // Generate PKCE code verifier and challenge
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    
    const clientId = process.env.MICROSOFT_CLIENT_ID;
    const redirectUri = `${process.env.URL}/.netlify/functions/auth-callback`;
    
    // Store code verifier (in production, use a proper session store)
    // For demo purposes, we'll return it to be stored client-side
    const state = generateState();
    
    const authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` +
      `client_id=${clientId}&` +
      `response_type=code&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `response_mode=query&` +
      `scope=${encodeURIComponent('openid profile email offline_access')}&` +
      `state=${state}&` +
      `code_challenge=${codeChallenge}&` +
      `code_challenge_method=S256`;

    return {
      statusCode: 200,
      headers: {
        ...headers,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        authUrl,
        codeVerifier,
        state
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: error.message })
    };
  }
};

// Helper functions
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(digest));
}

function base64URLEncode(array) {
  return btoa(String.fromCharCode.apply(null, array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// netlify/functions/auth-callback.js
// This function handles the OAuth callback and exchanges code for tokens
exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers };
  }

  try {
    const { code, state } = event.queryStringParameters;
    
    if (!code) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'No authorization code provided' })
      };
    }

    // In a real app, you'd verify the state parameter here
    // For this demo, we'll skip state verification
    
    // Get code verifier from query params or request body
    // In production, retrieve from secure session store
    const codeVerifier = event.queryStringParameters.code_verifier;
    
    if (!codeVerifier) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Code verifier is required' })
      };
    }

    const clientId = process.env.MICROSOFT_CLIENT_ID;
    const redirectUri = `${process.env.URL}/.netlify/functions/auth-callback`;
    
    // Exchange authorization code for tokens
    const tokenResponse = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: clientId,
        code: code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
        code_verifier: codeVerifier
      })
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: tokenData.error_description || 'Token exchange failed' })
      };
    }

    // Return tokens (in production, handle these securely)
    return {
      statusCode: 200,
      headers: {
        ...headers,
        'Content-Type': 'text/html'
      },
      body: `
        <html>
          <body>
            <h2>Authentication Successful!</h2>
            <p>Refresh Token: <code>${tokenData.refresh_token}</code></p>
            <p>Access Token: <code>${tokenData.access_token}</code></p>
            <p>Expires in: ${tokenData.expires_in} seconds</p>
            <script>
              // Store tokens securely (this is just for demo)
              localStorage.setItem('microsoft_refresh_token', '${tokenData.refresh_token}');
              localStorage.setItem('microsoft_access_token', '${tokenData.access_token}');
              
              // Optionally redirect back to your app
              // window.location.href = '/';
            </script>
          </body>
        </html>
      `
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: error.message })
    };
  }
};
