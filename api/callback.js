// Vercel Serverless Function - Exchange code for token
module.exports = async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { code, code_verifier } = req.body || {};

        if (!code || !code_verifier) {
            return res.status(400).json({ error: 'Missing code or code_verifier' });
        }

        const clientId = process.env.GITHUB_CLIENT_ID;
        const clientSecret = process.env.GITHUB_CLIENT_SECRET;
        const redirectUri = process.env.REDIRECT_URI;

        if (!clientId || !clientSecret) {
            return res.status(500).json({ error: 'Server configuration error' });
        }

        // Exchange code for token with GitHub
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                code: code,
                redirect_uri: redirectUri,
                code_verifier: code_verifier
            })
        });

        const data = await tokenResponse.json();

        if (data.error) {
            return res.status(400).json({ 
                error: data.error, 
                error_description: data.error_description 
            });
        }

        if (!data.access_token) {
            return res.status(400).json({ error: 'No access token received' });
        }

        return res.status(200).json({
            access_token: data.access_token,
            token_type: data.token_type || 'bearer'
        });

    } catch (error) {
        console.error('Error in callback:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};
