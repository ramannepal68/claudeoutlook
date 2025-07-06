// netlify/functions/refresh-token.js
// This function refreshes the access token using the refresh token
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
    const { refresh_token } = JSON.parse(event.body || '{}');
    
    if (!refresh_token) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Refresh token is required' })
      };
    }

    const clientId = process.env.MICROSOFT_CLIENT_ID;
    
    const tokenResponse = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: clientId,
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        scope: 'openid profile email offline_access'
      })
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: tokenData.error_description || 'Token refresh failed' })
      };
    }

    return {
      statusCode: 200,
      headers: {
        ...headers,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_in: tokenData.expires_in
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
