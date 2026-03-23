require("dotenv").config();
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const TOKENS_FILE = path.join(__dirname, "tokens.json");
const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, PORT = 3000, PASSWORD } = process.env;

// Security constants
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW = 60 * 1000; // 1 minute window for tracking attempts

// Security store: IP -> { attempts: number, lockedUntil: timestamp, csrfToken: string }
const securityStore = new Map();

function loadTokens() {
  try {
    return JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveToken(token) {
  const tokens = loadTokens();
  if (!tokens.includes(token)) {
    tokens.push(token);
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
  }
}

function getSecurityRecord(ip) {
  const now = Date.now();
  let record = securityStore.get(ip);

  if (!record) {
    record = { attempts: 0, lockedUntil: 0, csrfToken: crypto.randomBytes(32).toString("hex") };
    securityStore.set(ip, record);
  }

  // Clear attempts if window has passed
  if (record.lastAttempt && now - record.lastAttempt > ATTEMPT_WINDOW) {
    record.attempts = 0;
  }

  // Check if lockout has expired
  if (record.lockedUntil && now > record.lockedUntil) {
    record.lockedUntil = 0;
    record.attempts = 0;
  }

  return record;
}

function checkSecurity(ip) {
  const record = getSecurityRecord(ip);

  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    const minutesRemaining = Math.ceil((record.lockedUntil - Date.now()) / 60000);
    return { allowed: false, reason: `Account locked. Try again in ${minutesRemaining} minutes.` };
  }

  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const record = getSecurityRecord(ip);
  record.attempts++;
  record.lastAttempt = Date.now();

  if (record.attempts >= MAX_FAILED_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCKOUT_DURATION;
  }
}

function resetAttempts(ip) {
  const record = getSecurityRecord(ip);
  record.attempts = 0;
  record.lastAttempt = 0;
}

function generateNewCSRFToken(ip) {
  const record = getSecurityRecord(ip);
  record.csrfToken = crypto.randomBytes(32).toString("hex");
  return record.csrfToken;
}

app.use(express.json());

// Landing page
app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><title>Donate GitHub Token</title></head>
<body style="font-family:system-ui;max-width:480px;margin:80px auto;text-align:center">
  <h1>Donate a GitHub Token</h1>
  <p>This authorizes read-only access to public info (commits, stars, etc). No private data is accessed.</p>
  <a href="https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope="
     style="display:inline-block;padding:12px 24px;background:#24292e;color:#fff;border-radius:6px;text-decoration:none">
    Sign in with GitHub
  </a>
  <p style="color:#666;font-size:0.85em;margin-top:24px">${loadTokens().length} tokens donated so far</p>
</body></html>`);
});

// OAuth callback
app.get("/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send("Missing code parameter");

  try {
    const resp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
      }),
    });
    const data = await resp.json();

    if (data.access_token) {
      saveToken(data.access_token);
      res.send(`<!DOCTYPE html>
<html><head><title>Thanks!</title></head>
<body style="font-family:system-ui;max-width:480px;margin:80px auto;text-align:center">
  <h1>Thanks!</h1>
  <p>Your token has been donated. You can revoke it anytime from your
  <a href="https://github.com/settings/applications">GitHub settings</a>.</p>
</body></html>`);
    } else {
      res.status(400).send("OAuth failed: " + (data.error_description || data.error));
    }
  } catch (err) {
    res.status(500).send("Server error: " + err.message);
  }
});

// Tokens page - GET
app.get("/tokens", (req, res) => {
  const ip = req.ip;
  const csrfToken = generateNewCSRFToken(ip);

  res.send(`<!DOCTYPE html>
<html><head><title>Access Tokens</title></head>
<body style="font-family:system-ui;max-width:480px;margin:80px auto;text-align:center">
  <h1>Access Tokens</h1>
  <form id="form">
    <input type="password" id="password" placeholder="Enter password" required style="padding:8px;width:200px;border:1px solid #ccc;border-radius:4px">
    <button type="submit" style="padding:8px 16px;background:#24292e;color:#fff;border:none;border-radius:4px;cursor:pointer">Get Tokens</button>
  </form>
  <div id="result" style="margin-top:20px"></div>
  <script>
    const csrfToken = '${csrfToken}';
    document.getElementById('form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;
      const resultDiv = document.getElementById('result');
      resultDiv.innerHTML = '<p>Loading...</p>';

      try {
        const resp = await fetch('/tokens', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password, csrfToken })
        });

        const data = await resp.json();
        if (resp.ok) {
          resultDiv.innerHTML = '<h3>Tokens:</h3><pre style="background:#f6f8fa;padding:12px;border-radius:6px;text-align:left;overflow-x:auto;word-break:break-all">' +
            data.tokens.join(', ') + '</pre>';
        } else {
          resultDiv.innerHTML = '<p style="color:red">' + (data.error || 'Invalid password') + '</p>';
        }
      } catch (err) {
        resultDiv.innerHTML = '<p style="color:red">Error: ' + err.message + '</p>';
      }
    });
  </script>
</body></html>`);
});

// Tokens page - POST
app.post("/tokens", (req, res) => {
  const ip = req.ip;
  const { password, csrfToken } = req.body;

  // Check security status
  const security = checkSecurity(ip);
  if (!security.allowed) {
    return res.status(429).json({ error: security.reason });
  }

  // Validate CSRF token
  const record = getSecurityRecord(ip);
  if (!csrfToken || csrfToken !== record.csrfToken) {
    recordFailedAttempt(ip);
    return res.status(403).json({ error: "Invalid request. Please refresh and try again." });
  }

  // Validate password
  if (!password || password !== PASSWORD) {
    recordFailedAttempt(ip);
    const remaining = MAX_FAILED_ATTEMPTS - record.attempts;
    return res.status(401).json({ error: `Invalid password. ${remaining} attempts remaining.` });
  }

  // Success
  resetAttempts(ip);
  const tokens = loadTokens();
  res.json({ tokens });
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
