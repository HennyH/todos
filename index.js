// index.js - GitHub-as-Database Todo App with Dual Encryption
// Run this in an HTML page with <script type="module" src="index.js"></script>

const CONFIG = {
  REPO_OWNER: 'HennyH',        // e.g., 'alice'
  REPO_NAME: 'todos',             // e.g., 'todo-store'
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
  // Add leading zeros for each leading zero byte
  for (let byte of bytes) if (byte === 0) str = '1' + str;
  return str;
};

const ab2b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b642ab = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

// --- Cryptography Layer ---
class CryptoManager {
  async generateIdentity() {
    const keys = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true, // extractable for storage
      ['deriveKey', 'deriveBits']
    );
    const pubJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);

    // Derive address from public key raw bytes
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

    // Generate content encryption key (CEK)
    const cek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'wrapKey']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, data);

    // Helper to wrap CEK for a recipient
    const wrapForRecipient = async (recipientPub, kid) => {
      // Generate ephemeral keypair
      const ephemeral = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
      );

      // Derive shared secret
      const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipientPub }, ephemeral.privateKey, 256
      );

      // Derive wrapping key via HKDF-like simplified derivation (for PoC)
      // In production, use proper HKDF with salt/info
      const wrapKey = await crypto.subtle.importKey(
        'raw', sharedBits, { name: 'AES-KW' }, false, ['wrapKey']
      );

      // Wrap the CEK
      const wrapped = await crypto.subtle.wrapKey('raw', cek, wrapKey, 'AES-KW');

      const ephemeralPub = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
      return { kid, epk: ab2b64(ephemeralPub), wk: ab2b64(wrapped) };
    };

    const recipients = await Promise.all([
      wrapForRecipient(userPublicKey, 'user'),
      wrapForRecipient(shopPub, 'shop')
    ]);

    return {
      v: 1,
      iv: ab2b64(iv),
      ct: ab2b64(ciphertext),
      rec: recipients
    };
  }

  async decrypt(encryptedPackage, userPrivateKey, kid = 'user') {
    const rec = encryptedPackage.rec.find(r => r.kid === kid);
    if (!rec) throw new Error(`No recipient found for ${kid}`);

    // Reconstruct shared secret
    const ephemeralPub = await crypto.subtle.importKey(
      'raw', b642ab(rec.epk), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeralPub }, userPrivateKey, 256
    );
    const wrapKey = await crypto.subtle.importKey(
      'raw', sharedBits, { name: 'AES-KW' }, false, ['unwrapKey']
    );

    // Unwrap CEK
    const cek = await crypto.subtle.unwrapKey(
      'raw', b642ab(rec.wk), wrapKey, 'AES-KW', 
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    // Decrypt content
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
      if (res.status === 404) return []; // New user
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

    // 1. Get main branch SHA
    const mainRef = await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/git/ref/heads/main`, {
      headers: { Authorization: `token ${this.token}`, Accept: 'application/vnd.github.v3+json' }
    }).then(r => r.json());

    // 2. Create new branch
    await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/git/refs`, {
      method: 'POST',
      headers: { Authorization: `token ${this.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: mainRef.object.sha })
    });

    // 3. Get current file SHA if exists (to update vs create)
    let currentSha;
    try {
      const current = await fetch(`${this.api}/repos/${CONFIG.REPO_OWNER}/${CONFIG.REPO_NAME}/contents/${path}?ref=main`, {
        headers: { Authorization: `token ${this.token}` }
      }).then(r => { if(r.ok) return r.json(); throw new Error('404'); });
      currentSha = current.sha;
    } catch (e) { /* File doesn't exist yet */ }

    // 4. Create/update file on new branch
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

    // 5. Create PR
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
        <h1>GitHub Todo</h1>
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
    const identity = localStorage.getItem('todo_identity');
    const token = localStorage.getItem('todo_token');

    if (!identity) {
      await this.setupIdentity();
    } else if (!token) {
      this.showTokenInput();
    } else {
      const id = await this.crypto.loadIdentity(JSON.parse(identity));
      this.store = new GitHubStore(token, id);
      this.elements.auth.style.display = 'none';
      this.elements.todos.style.display = 'block';
      this.elements.userInfo.textContent = `Identity: ${id.address.substring(0, 16)}...`;
      this.loadTodos();
    }
  }

  async setupIdentity() {
    this.elements.auth.innerHTML = `
      <div style="padding:20px;border:1px solid #ddd;border-radius:8px;">
        <p>No identity found. Click below to generate cryptographic keys.</p>
        <button id="btn-generate" style="padding:10px 20px;background:#0366d6;color:white;border:0;border-radius:6px;cursor:pointer;">
          Generate Identity
        </button>
        <div id="gen-status" style="margin-top:10px;font-size:0.9em;"></div>
      </div>
    `;

    document.getElementById('btn-generate').onclick = async () => {
      document.getElementById('gen-status').textContent = 'Generating...';
      const id = await this.crypto.generateIdentity();
      localStorage.setItem('todo_identity', JSON.stringify({
        privateKey: id.privateKey,
        publicKey: id.publicKey,
        address: id.address
      }));
      document.getElementById('gen-status').innerHTML = 
        `<strong>Generated!</strong><br>Address: <code>${id.address}</code><br>Save this somewhere safe.`;
      setTimeout(() => this.checkAuth(), 2000);
    };
  }

  showTokenInput() {
    this.elements.auth.innerHTML = `
      <div style="padding:20px;border:1px solid #ddd;border-radius:8px;">
        <p>Enter GitHub Personal Access Token with <code>public_repo</code> scope:</p>
        <input type="password" id="token-input" style="width:100%;padding:8px;margin-bottom:10px;" placeholder="ghp_...">
        <button id="btn-login" style="padding:10px 20px;background:#0366d6;color:white;border:0;border-radius:6px;cursor:pointer;">
          Connect
        </button>
        <p style="font-size:0.85em;color:#666;margin-top:10px;">
          Your token is stored locally and used only to create PRs.
        </p>
      </div>
    `;

    document.getElementById('btn-login').onclick = () => {
      const token = document.getElementById('token-input').value;
      if (token) {
        localStorage.setItem('todo_token', token);
        this.checkAuth();
      }
    };
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
      this.elements.syncStatus.innerHTML = `✓ Created PR: <a href="${prUrl}" target="_blank">${prUrl}</a><br>
        <em>The bot will auto-merge shortly.</em>`;
    } catch (e) {
      this.elements.syncStatus.textContent = 'Error: ' + e.message;
      console.error(e);
    } finally {
      this.elements.syncBtn.disabled = false;
    }
  }

  logout() {
    localStorage.removeItem('todo_token');
    location.reload();
  }
}

// Initialize
window.app = new TodoApp();
app.init();
