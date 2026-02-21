// Vercel Serverless Function
// Environment variables: GITHUB_CLIENT_ID, REDIRECT_URI (your GitHub Pages URL)

function generateRandomString(length) {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let text = '';
    for (let i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

async function sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return await crypto.subtle.digest('SHA-256', data);
}

function base64urlencode(str) {
    return btoa(String.fromCharCode(...new Uint8Array(str)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

export default async function handler(req, res) {
    // Enable CORS for your GitHub Pages domain
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const clientId = process.env.GITHUB_CLIENT_ID;
    const redirectUri = process.env.REDIRECT_URI; // e.g., https://username.github.io/repo-name/

    // PKCE
    const codeVerifier = generateRandomString(128);
    const codeChallenge = base64urlencode(await sha256(codeVerifier));
    const state = generateRandomString(32);

    const loginUrl = `https://github.com/login/oauth/authorize?` + 
        `client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=repo` +
        `&state=${state}` +
        `&code_challenge=${codeChallenge}` +
        `&code_challenge_method=S256`;

    return res.json({
        login_url: loginUrl,
        code_verifier: codeVerifier,
        state: state
    });
}
