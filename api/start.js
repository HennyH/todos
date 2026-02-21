// Vercel Serverless Function - CommonJS format (no ES module issues)
const crypto = require('crypto');

function generateRandomString(length) {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let text = '';
    for (let i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

function base64urlencode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

module.exports = async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const clientId = process.env.GITHUB_CLIENT_ID;
        const redirectUri = process.env.REDIRECT_URI;

        if (!clientId || !redirectUri) {
            return res.status(500).json({ error: 'Server configuration error' });
        }

        // PKCE
        const code_verifier = generateRandomString(128);
        const hash = crypto.createHash('sha256').update(code_verifier).digest();
        const code_challenge = base64urlencode(hash);
        const state = generateRandomString(32);

        const loginUrl = 'https://github.com/login/oauth/authorize?' + [
            `client_id=${clientId}`,
            `redirect_uri=${encodeURIComponent(redirectUri)}`,
            'scope=repo',
            `state=${state}`,
            `code_challenge=${code_challenge}`,
            'code_challenge_method=S256'
        ].join('&');

        return res.status(200).json({
            login_url: loginUrl,
            code_verifier: code_verifier,
            state: state
        });

    } catch (error) {
        console.error('Error in start:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};
