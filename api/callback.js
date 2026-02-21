// Vercel Serverless Function
// Environment variables: GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, REDIRECT_URI

export default async function handler(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({error:'Method not allowed'});

    const { code, code_verifier } = req.body;

    if (!code || !code_verifier) {
        return res.status(400).json({ error: 'Missing code or verifier' });
    }

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            client_id: process.env.GITHUB_CLIENT_ID,
            client_secret: process.env.GITHUB_CLIENT_SECRET,
            code: code,
            redirect_uri: process.env.REDIRECT_URI,
            code_verifier: code_verifier
        })
    });

    const data = await tokenRes.json();

    if (data.error) {
        return res.status(400).json(data);
    }

    // Return only the access token (and optional refresh token if you requested offline access)
    return res.json({
        access_token: data.access_token,
        token_type: data.token_type
    });
}
