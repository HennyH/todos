// index.js - GitHub-as-Database Todo App with Dual Encryption
// Run this in an HTML page with <script type="module" src="index.js"></script>

const CONFIG = {
  REPO_OWNER: 'HennyH',        // e.g., 'alice'`
  REPO_NAME: 'todos',             // e.g., 'todo-store'
  OAUTH_CLIENT_ID: 'Ov23li18WS1xOuEI7S4m',
  SHOP_PUBLIC_KEY_JWK: {
    kty: "EC",
    crv: "P-256",
    x: "M6JVZzBRi1YUTsC6Zr1jmaJ0h7fJznx5voY6wrxka-E",
    y:"wPDtNEu87t8qV9XXHR74dYAYda46yZSuuq_r9Knz6QI"
  }
};

// --- Utilities ---
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base58Encode = (bytes) => {
  let num = BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  let str = '';
  while (num > 0) {
    str = B58_ALPHABET[Number(num % 58n)] + str;
    num = num / 58n;
  }
  for (let byte of bytes) if (byte === 0) str = '1' + str;
  return str;
};

const ab2b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const b642ab = (b64) => {
  b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
};

const generateRandomString = (length) => {
  const array = new Uint8Array(Math.ceil(length * 3 / 4));
  crypto.getRandomValues(array);
  return ab2b64(array).substring(0, length);
};

// --- PKCE & OAuth2 Utilities ---
class OAuth2Client {
  constructor(clientId) {
    this.clientId = clientId;
    this.redirectUri = window.location.origin + window.location.pathname;
  }

  async generatePKCE() {
    const verifier = generateRandomString(128);
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = ab2b64(hashBuffer);
    return { verifier, challenge };
  }

  async initiateLogin() {
    const { verifier, challenge } = await this.generatePKCE();
    const state = generateRandomString(32);

    // Store for callback verification
    sessionStorage.setItem('oauth_verifier', verifier);
    sessionStorage.setItem('oauth_state', state);

    // GitHub OAuth2 Authorization endpoint with PKCE
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'public_repo',  // or 'repo' if using private repository
      response_type: 'code',
      state: state,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });

    window.location.href = `https://github.com/login/oauth/authorize?${params}`;
  }

  async handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');

    if (error) throw new Error(`OAuth error: ${error}`);
    if (!code) return null; // Not a callback

    // Verify state to prevent CSRF
    const savedState = sessionStorage.getItem('oauth_state');
    if (state !== savedState) throw new Error('Invalid state parameter');

    const verifier = sessionStorage.getItem('oauth_verifier');
    if (!verifier) throw new Error('PKCE verifier not found');

    // Exchange code for token using GitHub's token endpoint via CORS proxy
    // GitHub's token endpoint doesn't support CORS for browser requests directly,
    // so we use a lightweight token exchange strategy
    const token = await this.exchangeCode(code, verifier);

    // Clean up URL and storage
    window.history.replaceState({}, document.title, window.location.pathname);
    sessionStorage.removeItem('oauth_verifier');
    sessionStorage.removeItem('oauth_state');

    return token;
  }

  async exchangeCode(code, verifier) {
    // GitHub's token endpoint doesn't support CORS from browsers.
    // Solution: Use a serverless proxy OR use the device flow.
    // For pure GitHub Pages (no external server), we have two options:

    // OPTION A: GitHub Actions token exchange (async, via repository_dispatch)
    // This creates a workflow that exchanges the code and commits the token encrypted to a temp file

    // OPTION B: Use a minimal CORS proxy (e.g., https://cors-anywhere.herokuapp.com - not recommended for prod)
    // or set up your own Cloudflare Worker (2 lines of code)

    // For this implementation, we'll use a hybrid approach:
    // Store the code, trigger a workflow via dispatch, poll for result

    return await this.exchangeViaGitHubActions(code, verifier);
  }

  async exchangeViaGitHubActions(code, verifier) {
    // This uses the repository_dispatch flow we discussed earlier
    // But for UX simplicity, we'll show the direct exchange (requires CORS proxy for production)

    // For local development or if you have a CORS proxy:
    if (window.location.hostname === 'localhost') {
      // Direct exchange - works if you have a local proxy or disabled CORS for dev
      const response = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Origin': window.location.origin
        },
        body: JSON.stringify({
          client_id: this.clientId,
          code: code,
          redirect_uri: this.redirectUri,
          code_verifier: verifier
        })
      });

      if (!response.ok) throw new Error('Token exchange failed');
      const data = await response.json();
      if (data.error) throw new Error(data.error_description || data.error);
      return data.access_token;
    }

    // For production GitHub Pages without CORS proxy:
    // Use the async workflow approach
    throw new Error('Production deployment requires a CORS proxy or serverless token exchange. See implementation comments.');
  }
}

// --- Cryptography Layer ---
class CryptoManager {
  async generateIdentity() {
    const keys = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true, ['deriveKey', 'deriveBits']
    );
    const pubJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);

    const rawPub = await crypto.subtle.exportKey('raw', keys.publicKey);
    const hash = await crypto.subtle.digest('SHA-256', rawPub);
    const address = base58Encode(new Uint8Array(hash).slice(0, 20));

    return { privateKey: privJwk, publicKey: pubJwk, address };
  }

  async loadIdentity(stored) {
    const privateKey = await crypto.subtle.importKey(
      'jwk', stored.privateKey, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk', stored.publicKey, { name: 'ECDH', namedCurve: 'P-256' }, true, []
    );
    return { privateKey, publicKey, address: stored.address };
  }

  async dualEncrypt(plaintextObj, userPublicKey, shopPublicKeyJwk) {
    const shopPub = await crypto.subtle.importKey(
      'jwk', shopPublicKeyJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []
    );

    const data = new TextEncoder().encode(JSON.stringify(plaintextObj));
    const cek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'wrapKey']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, data);

    const wrapForRecipient = async (recipientPub, kid) => {
      const ephemeral = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
      );

      const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipientPub }, ephemeral.privateKey, 256
      );

      const wrapKey = await crypto.subtle.importKey(
        'raw', sharedBits, { name: 'AES-KW' }, false, ['wrapKey']
      );

      const wrapped = await crypto.subtle.wrapKey('raw', cek, wrapKey, 'AES-KW');
      const ephemeralPub = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
      return { kid, epk: ab2b64(ephemeralPub), wk: ab2b64(wrapped) };
    };

    const recipients = await Promise.all([
      wrapForRecipient(userPublicKey, 'user'),
      wrapForRecipient(shopPub, 'shop')
    ]);

    return { v: 1, iv: ab2b64(iv), ct: ab2b64(ciphertext), rec: recipients };
  }

  async decrypt(encryptedPackage, userPrivateKey, kid = 'user') {
    const rec = encryptedPackage.rec.find(r => r.kid === kid);
    if (!rec) throw new Error(`No recipient found for ${kid}`);

    const ephemeralPub = await crypto.subtle.importKey(
      'raw', b642ab(rec.epk), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeralPub }, userPrivateKey, 256
    );
    const wrapKey = await crypto.subtle.importKey(
      'raw', sharedBits, { name: 'AES-KW' }, false, ['unwrapKey']
    );

    const cek = await crypto.subtle.unwrapKey(
      'raw', b642ab(rec.wk), wrapKey, 'AES-KW', 
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b642ab(encryptedPackage.iv) },
      cek, b642ab(encryptedPackage.ct)
    );

    return JSON.parse(new TextDecoder().decode(plaintext));
  }
}

// --- GitHub Data Layer ---
class GitHubStore {
  constructor(token, identity) {
    this.token = token;
    this.identity = identity;
    this.api = 'https://api.github.com';
    this.raw = `https://raw.githubusercontent.com/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/main`;
  }

  async fetchTodos() {
    const path = `data/users/${this.identity.address}/todos.json`;
    try {
      const res = await fetch(`${this.raw}/${path}`);
      if (res.status === 404) return [];
      if (!res.ok) throw new Error('Fetch failed');
      const encrypted = await res.json();
      return await new CryptoManager().decrypt(encrypted, this.identity.privateKey);
    } catch (e) {
      console.error('Failed to load todos:', e);
      return [];
    }
  }

  async saveTodos(todos) {
    const crypto = new CryptoManager();
    const userPub = await crypto.subtle.importKey(
      'jwk', JSON.parse(localStorage.getItem('todo_identity')).publicKey,
      { name: 'ECDH', namedCurve: 'P-256' }, true, []
    );

    const encrypted = await crypto.dualEncrypt(todos, userPub, CONFIG.SHOP_PUBLIC_KEY_JWK);
    const content = JSON.stringify(encrypted, null, 2);
    const b64Content = btoa(content);

    const path = `data/users/${this.identity.address}/todos.json`;
    const branchName = `update-${Date.now()}`;

    const mainRef = await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/git/ref/heads/main`, {
      headers: { Authorization: `token ${this.token}`, Accept: 'application/vnd.github.v3+json' }
    }).then(r => r.json());

    await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/git/refs`, {
      method: 'POST',
      headers: { Authorization: `token ${this.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: mainRef.object.sha })
    });

    let currentSha;
    try {
      const current = await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/contents/${path}?ref=main`, {
        headers: { Authorization: `token ${this.token}` }
      }).then(r => { if(r.ok) return r.json(); throw new Error('404'); });
      currentSha = current.sha;
    } catch (e) { /* New file */ }

    await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/contents/${path}`, {
      method: 'PUT',
      headers: { Authorization: `token ${this.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: `Update todos for ${this.identity.address}`,
        content: b64Content,
        branch: branchName,
        ...(currentSha && { sha: currentSha })
      })
    });

    const pr = await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/pulls`, {
      method: 'POST',
      headers: { Authorization: `token ${this.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: `Todo update: ${this.identity.address}`,
        head: branchName,
        base: 'main',
        body: 'Automated todo list update'
      })
    }).then(r => r.json());

    return pr.html_url;
  }
}

// --- Application Layer ---
class TodoApp {
  constructor() {
    this.crypto = new CryptoManager();
    this.oauth = new OAuth2Client(CONFIG.OAUTH_CLIENT_ID);
    this.store = null;
    this.todos = [];
    this.elements = {};
  }

  init() {
    this.createUI();
    this.checkAuth();
  }

  createUI() {
    document.body.innerHTML = `
      <div id="app" style="max-width:600px;margin:50px auto;font-family:sans-serif;">
        <h1>GitHub Todo (OAuth2)</h1>
        <div id="auth-section"></div>
        <div id="todo-section" style="display:none;">
          <div style="margin-bottom:20px;">
            <span id="user-info" style="font-size:0.9em;color:#666;"></span>
            <button id="btn-logout" style="float:right;">Logout</button>
          </div>
          <div style="display:flex;gap:10px;margin-bottom:20px;">
            <input id="todo-input" type="text" placeholder="New todo..." style="flex:1;padding:8px;">
            <button id="btn-add" style="padding:8px 16px;">Add</button>
          </div>
          <div id="todo-list"></div>
          <div style="margin-top:20px;">
            <button id="btn-sync" style="width:100%;padding:10px;background:#2ea44f;color:white;border:0;border-radius:6px;cursor:pointer;">
              Sync to GitHub (Create PR)
            </button>
            <div id="sync-status" style="margin-top:10px;font-size:0.85em;color:#666;"></div>
          </div>
        </div>
      </div>
    `;

    this.elements = {
      auth: document.getElementById('auth-section'),
      todos: document.getElementById('todo-section'),
      input: document.getElementById('todo-input'),
      list: document.getElementById('todo-list'),
      syncBtn: document.getElementById('btn-sync'),
      syncStatus: document.getElementById('sync-status'),
      userInfo: document.getElementById('user-info')
    };

    document.getElementById('btn-add').onclick = () => this.addTodo();
    document.getElementById('btn-logout').onclick = () => this.logout();
    this.elements.syncBtn.onclick = () => this.sync();
    this.elements.input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addTodo();
    });
  }

  async checkAuth() {
    // Check for OAuth callback first
    if (window.location.search.includes('code=')) {
      try {
        this.elements.auth.innerHTML = '<p>Completing OAuth login...</p>';
        const token = await this.oauth.handleCallback();
        if (token) {
          sessionStorage.setItem('oauth_token', token);
        }
      } catch (e) {
        this.elements.auth.innerHTML = `<p style="color:red;">Login failed: ${e.message}</p>`;
        console.error(e);
        return;
      }
    }

    const identity = localStorage.getItem('todo_identity');
    const token = sessionStorage.getItem('oauth_token');

    if (!identity) {
      await this.setupIdentity();
    } else if (!token) {
      this.showOAuthLogin();
    } else {
      try {
        const id = await this.crypto.loadIdentity(JSON.parse(identity));
        this.store = new GitHubStore(token, id);
        this.elements.auth.style.display = 'none';
        this.elements.todos.style.display = 'block';
        this.elements.userInfo.textContent = `Identity: ${id.address.substring(0, 16)}... | Token: ${token.substring(0, 8)}...`;
        this.loadTodos();
      } catch (e) {
        console.error('Failed to load identity:', e);
        this.logout();
      }
    }
  }

  async setupIdentity() {
    this.elements.auth.innerHTML = `
      <div style="padding:20px;border:1px solid #ddd;border-radius:8px;">
        <p>Welcome! First, generate your cryptographic identity.</p>
        <button id="btn-generate" style="padding:10px 20px;background:#0366d6;color:white;border:0;border-radius:6px;cursor:pointer;">
          Generate Identity
        </button>
        <div id="gen-status" style="margin-top:10px;font-size:0.9em;"></div>
      </div>
    `;

    document.getElementById('btn-generate').onclick = async () => {
      document.getElementById('gen-status').textContent = 'Generating P-256 keypair...';
      const id = await this.crypto.generateIdentity();
      localStorage.setItem('todo_identity', JSON.stringify({
        privateKey: id.privateKey,
        publicKey: id.publicKey,
        address: id.address
      }));
      document.getElementById('gen-status').innerHTML = 
        `<strong>✓ Generated!</strong><br>Address: <code>${id.address}</code><br><em>Save this address - it identifies your data folder.</em>`;
      setTimeout(() => this.checkAuth(), 2000);
    };
  }

  showOAuthLogin() {
    this.elements.auth.innerHTML = `
      <div style="padding:20px;border:1px solid #ddd;border-radius:8px;">
        <p>Connect to GitHub to sync your encrypted todos.</p>
        <button id="btn-oauth" style="padding:12px 24px;background:#24292f;color:white;border:0;border-radius:6px;cursor:pointer;font-weight:bold;">
          <svg height="20" width="20" viewBox="0 0 16 16" style="fill:currentColor;vertical-align:middle;margin-right:8px;">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
          </svg>
          Login with GitHub
        </button>
        <p style="font-size:0.85em;color:#666;margin-top:15px;">
          No server involved. Uses PKCE (Proof Key for Code Exchange) for secure OAuth2 flow.
          Your token is stored only in session memory.
        </p>
      </div>
    `;

    document.getElementById('btn-oauth').onclick = () => this.oauth.initiateLogin();
  }

  async loadTodos() {
    this.todos = await this.store.fetchTodos();
    this.renderTodos();
  }

  renderTodos() {
    if (this.todos.length === 0) {
      this.elements.list.innerHTML = '<p style="color:#999;">No todos yet. Add one above.</p>';
      return;
    }

    this.elements.list.innerHTML = this.todos.map((todo, i) => `
      <div style="display:flex;align-items:center;padding:10px;border-bottom:1px solid #eee;">
        <input type="checkbox" ${todo.done ? 'checked' : ''} 
               onchange="window.app.toggleTodo(${i})" style="margin-right:10px;">
        <span style="${todo.done ? 'text-decoration:line-through;color:#999;' : ''}">${this.escapeHtml(todo.text)}</span>
        <button onclick="window.app.deleteTodo(${i})" style="margin-left:auto;color:#d73a49;background:none;border:0;cursor:pointer;">×</button>
      </div>
    `).join('');
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  addTodo() {
    const text = this.elements.input.value.trim();
    if (!text) return;
    this.todos.push({ text, done: false, created: Date.now() });
    this.elements.input.value = '';
    this.renderTodos();
  }

  toggleTodo(index) {
    this.todos[index].done = !this.todos[index].done;
    this.renderTodos();
  }

  deleteTodo(index) {
    this.todos.splice(index, 1);
    this.renderTodos();
  }

  async sync() {
    this.elements.syncBtn.disabled = true;
    this.elements.syncStatus.textContent = 'Creating encrypted blob and pull request...';
    try {
      const prUrl = await this.store.saveTodos(this.todos);
      this.elements.syncStatus.innerHTML = `✓ Created PR: <a href="${prUrl}" target="_blank">View on GitHub</a><br><em>Bot will auto-merge shortly.</em>`;
    } catch (e) {
      this.elements.syncStatus.textContent = 'Error: ' + e.message;
      console.error(e);
    } finally {
      this.elements.syncBtn.disabled = false;
    }
  }

  logout() {
    sessionStorage.removeItem('oauth_token');
    localStorage.removeItem('todo_identity');
    location.reload();
  }
}

// Initialize
window.app = new TodoApp();
app.init();