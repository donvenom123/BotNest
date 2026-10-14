const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "https://donvenom123.github.io";

const SESSION_HOURS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_ACTIVE_SESSIONS = 10000;

const OWNER_EMAIL = (process.env.BOTNEST_OWNER_EMAIL || "")
  .trim()
  .toLowerCase();

const OWNER_PASSWORD =
  process.env.BOTNEST_OWNER_PASSWORD || "";

const OWNER_WORKSPACE_ID =
  process.env.BOTNEST_OWNER_WORKSPACE_ID || "";

const ALLOW_REGISTRATION =
  process.env.BOTNEST_ALLOW_REGISTRATION === "true";

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000
    })
  : null;

app.disable("x-powered-by");

app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "1mb" }));

const loginAttempts = new Map();

function getClientKey(req) {
  return req.ip || req.socket.remoteAddress || "unknown";
}

function isRateLimited(key) {
  const now = Date.now();
  let entry = loginAttempts.get(key);

  if (!entry || now - entry.startedAt > LOGIN_WINDOW_MS) {
    entry = { startedAt: now, count: 0 };
    loginAttempts.set(key, entry);
  }

  entry.count += 1;
  return entry.count > MAX_LOGIN_ATTEMPTS;
}

function clearLoginAttempts(key) {
  loginAttempts.delete(key);
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function safeEqualStrings(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  const leftHash = crypto
    .createHash("sha256")
    .update(left)
    .digest();

  const rightHash = crypto
    .createHash("sha256")
    .update(right)
    .digest();

  const equalLength = left.length === right.length;
  const equalHash = crypto.timingSafeEqual(leftHash, rightHash);

  return equalLength && equalHash;
}

function validOwnerConfiguration() {
  return Boolean(
    OWNER_EMAIL &&
    OWNER_PASSWORD.length >= 16 &&
    /^[a-zA-Z0-9_-]{8,100}$/.test(OWNER_WORKSPACE_ID)
  );
}

function normalizeEmail(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}

function validEmail(email) {
  return (
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 256
  );
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(password, salt, 64);

  return (
    salt.toString("hex") +
    ":" +
    derivedKey.toString("hex")
  );
}

function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split(":");

    if (parts.length !== 2) return false;

    const salt = Buffer.from(parts[0], "hex");
    const expected = Buffer.from(parts[1], "hex");

    if (salt.length !== 16 || expected.length !== 64) {
      return false;
    }

    const actual = crypto.scryptSync(password, salt, 64);

    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function createToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function normalizeChecks(value) {
  if (!Array.isArray(value)) {
    return [false, false, false, false];
  }

  return [0, 1, 2, 3].map(i => value[i] === true);
}

function formatProject(row) {
  return {
    id: row.id,
    name: row.name,
    platform: row.platform,
    status: row.status,
    checks: normalizeChecks(row.checks),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

let tableReady;

async function ensureTable() {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured.");
  }

  if (!tableReady) {
    tableReady = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS botnest_projects (
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          name VARCHAR(100) NOT NULL,
          platform VARCHAR(20) NOT NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'setup_required',
          checks JSONB NOT NULL
            DEFAULT '[false,false,false,false]'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS botnest_projects_workspace_idx
          ON botnest_projects (workspace_id);

        CREATE TABLE IF NOT EXISTS botnest_sessions (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT,
          workspace_id TEXT,
          is_owner BOOLEAN NOT NULL DEFAULT FALSE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          expires_at TIMESTAMPTZ NOT NULL
        );

        CREATE INDEX IF NOT EXISTS botnest_sessions_expiry_idx
          ON botnest_sessions (expires_at);

        CREATE TABLE IF NOT EXISTS botnest_settings (
          setting_key TEXT PRIMARY KEY,
          setting_value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS botnest_users (
          id TEXT PRIMARY KEY,
          email VARCHAR(254) NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          workspace_id TEXT NOT NULL UNIQUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Upgrade an existing sessions table without deleting sessions
      // or modifying existing project records.
      await pool.query(`
        ALTER TABLE botnest_sessions
          ADD COLUMN IF NOT EXISTS user_id TEXT;

        ALTER TABLE botnest_sessions
          ADD COLUMN IF NOT EXISTS workspace_id TEXT;

        ALTER TABLE botnest_sessions
          ADD COLUMN IF NOT EXISTS is_owner BOOLEAN
          NOT NULL DEFAULT FALSE;
      `);
    })().catch(error => {
      tableReady = null;
      throw error;
    });
  }

  await tableReady;
}

function getSessionFromRequest(req) {
  const header = req.get("Authorization") || "";
  const match = header.match(/^Bearer ([A-Za-z0-9_-]{40,200})$/);

  return match ? match[1] : null;
}

async function createSession(user) {
  const token = createToken();
  const tokenHash = sha256(token);

  await pool.query(
    `INSERT INTO botnest_sessions
       (token_hash, user_id, workspace_id, is_owner, expires_at)
     VALUES ($1, $2, $3, $4, NOW() + INTERVAL '12 hours')`,
    [
      tokenHash,
      user.id || null,
      user.workspaceId,
      user.isOwner === true
    ]
  );

  return token;
}

async function authenticate(req, res, next) {
  try {
    const token = getSessionFromRequest(req);

    if (!token) {
      return res.status(401).json({
        error: "Please sign in to BotNest."
      });
    }

    await ensureTable();

    const tokenHash = sha256(token);

    const result = await pool.query(
      `SELECT token_hash, user_id, workspace_id, is_owner,
              created_at, expires_at
       FROM botnest_sessions
       WHERE token_hash = $1
         AND expires_at > NOW()
       LIMIT 1`,
      [tokenHash]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Session expired. Please sign in again."
      });
    }

    const session = result.rows[0];

    if (!session.workspace_id) {
      return res.status(401).json({
        error: "This session is invalid. Please sign in again."
      });
    }

    req.sessionTokenHash = tokenHash;
    req.userId = session.user_id;
    req.workspaceId = session.workspace_id;
    req.isOwner = session.is_owner === true;

    next();
  } catch (error) {
    next(error);
  }
}

app.get("/", (req, res) => {
  res.json({
    name: "BotNest API",
    status: "online"
  });
});

app.get("/health", async (req, res) => {
  try {
    if (!pool) {
      return res.status(503).json({
        status: "error",
        service: "BotNest API",
        database: "not_configured"
      });
    }

    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      service: "BotNest API",
      database: "connected"
    });
  } catch {
    console.error("Database health check failed.");

    res.status(503).json({
      status: "error",
      service: "BotNest API",
      database: "unavailable"
    });
  }
});

app.get("/api/auth/status", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    configured: validOwnerConfiguration(),
    registration: ALLOW_REGISTRATION ? "enabled" : "disabled"
  });
});

// Register a new user with a separate workspace.
app.post("/api/auth/register", async (req, res, next) => {
  try {
    if (!ALLOW_REGISTRATION) {
      return res.status(403).json({
        error: "Registration is currently disabled."
      });
    }

    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: "Password must be between 12 and 256 characters."
      });
    }

    if (OWNER_EMAIL && safeEqualStrings(email, OWNER_EMAIL)) {
      return res.status(409).json({
        error: "This email cannot be registered."
      });
    }

    await ensureTable();

    const existing = await pool.query(
      "SELECT id FROM botnest_users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const userId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const passwordHash = hashPassword(password);

    try {
      await pool.query(
        `INSERT INTO botnest_users
           (id, email, password_hash, workspace_id)
         VALUES ($1, $2, $3, $4)`,
        [userId, email, passwordHash, workspaceId]
      );
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "An account with this email already exists."
        });
      }

      throw error;
    }

    const token = await createSession({
      id: userId,
      workspaceId,
      isOwner: false
    });

    res.set("Cache-Control", "no-store");

    res.status(201).json({
      token,
      expiresInSeconds: SESSION_HOURS * 60 * 60,
      owner: false,
      user: { email }
    });
  } catch (error) {
    next(error);
  }
});

// Sign in either as the configured owner or a registered user.
app.post("/api/auth/login", async (req, res, next) => {
  const key = getClientKey(req);

  try {
    if (isRateLimited(key)) {
      return res.status(429).json({
        error: "Too many login attempts. Try again later."
      });
    }

    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === "string"
      ? req.body.password
      : "";

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    await ensureTable();

    // Existing owner credentials continue to work.
    if (
      validOwnerConfiguration() &&
      safeEqualStrings(email, OWNER_EMAIL) &&
      safeEqualStrings(password, OWNER_PASSWORD)
    ) {
      const token = await createSession({
        id: null,
        workspaceId: OWNER_WORKSPACE_ID,
        isOwner: true
      });

      clearLoginAttempts(key);
      res.set("Cache-Control", "no-store");

      return res.json({
        token,
        expiresInSeconds: SESSION_HOURS * 60 * 60,
        owner: true,
        user: { email: OWNER_EMAIL }
      });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash, workspace_id
       FROM botnest_users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    const user = result.rows[0];

    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const token = await createSession({
      id: user.id,
      workspaceId: user.workspace_id,
      isOwner: false
    });

    clearLoginAttempts(key);
    res.set("Cache-Control", "no-store");

    res.json({
      token,
      expiresInSeconds: SESSION_HOURS * 60 * 60,
      owner: false,
      user: { email: user.email }
    });
  } catch (error) {
    next(error);
  }
});

// Invalidate a session.
app.post("/api/auth/logout", authenticate, async (req, res, next) => {
  try {
    await pool.query(
      "DELETE FROM botnest_sessions WHERE token_hash = $1",
      [req.sessionTokenHash]
    );

    res.set("Cache-Control", "no-store");
    res.json({ loggedOut: true });
  } catch (error) {
    next(error);
  }
});

// Return the currently authenticated user.
app.get("/api/auth/me", authenticate, async (req, res, next) => {
  try {
    res.set("Cache-Control", "no-store");

    if (req.isOwner) {
      return res.json({
        authenticated: true,
        owner: true,
        user: { email: OWNER_EMAIL }
      });
    }

    const result = await pool.query(
      "SELECT email FROM botnest_users WHERE id = $1 LIMIT 1",
      [req.userId]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Account not found. Please sign in again."
      });
    }

    res.json({
      authenticated: true,
      owner: false,
      user: { email: result.rows[0].email }
    });
  } catch (error) {
    next(error);
  }
});

// List projects in the authenticated account's workspace.
app.get("/api/projects", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM botnest_projects
       WHERE workspace_id = $1
       ORDER BY created_at DESC`,
      [req.workspaceId]
    );

    res.set("Cache-Control", "no-store");

    res.json({
      projects: result.rows.map(formatProject)
    });
  } catch (error) {
    next(error);
  }
});

// Create a project.
app.post("/api/projects", authenticate, async (req, res, next) => {
  try {
    const { name, platform, checks } = req.body || {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.trim().length > 100
    ) {
      return res.status(400).json({
        error: "Enter a bot name of up to 100 characters."
      });
    }

    if (!["Discord", "WhatsApp", "Telegram"].includes(platform)) {
      return res.status(400).json({
        error: "Unsupported platform."
      });
    }

    const result = await pool.query(
      `INSERT INTO botnest_projects
         (id, workspace_id, name, platform, checks)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       RETURNING *`,
      [
        crypto.randomUUID(),
        req.workspaceId,
        name.trim(),
        platform,
        JSON.stringify(normalizeChecks(checks))
      ]
    );

    res.status(201).json({
      project: formatProject(result.rows[0])
    });
  } catch (error) {
    next(error);
  }
});

// Update only projects belonging to the authenticated workspace.
app.patch("/api/projects/:id", authenticate, async (req, res, next) => {
  try {
    const { name, platform, checks } = req.body || {};

    if (
      name !== undefined &&
      (
        typeof name !== "string" ||
        !name.trim() ||
        name.trim().length > 100
      )
    ) {
      return res.status(400).json({
        error: "Invalid project name."
      });
    }

    if (
      platform !== undefined &&
      !["Discord", "WhatsApp", "Telegram"].includes(platform)
    ) {
      return res.status(400).json({
        error: "Unsupported platform."
      });
    }

    const result = await pool.query(
      `UPDATE botnest_projects
       SET name = COALESCE($1, name),
           platform = COALESCE($2, platform),
           checks = COALESCE($3::jsonb, checks),
           updated_at = NOW()
       WHERE id = $4 AND workspace_id = $5
       RETURNING *`,
      [
        name === undefined ? null : name.trim(),
        platform === undefined ? null : platform,
        checks === undefined
          ? null
          : JSON.stringify(normalizeChecks(checks)),
        req.params.id,
        req.workspaceId
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Project not found."
      });
    }

    res.json({
      project: formatProject(result.rows[0])
    });
  } catch (error) {
    next(error);
  }
});

// Delete only projects belonging to the authenticated workspace.
app.delete("/api/projects/:id", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `DELETE FROM botnest_projects
       WHERE id = $1 AND workspace_id = $2`,
      [req.params.id, req.workspaceId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Project not found."
      });
    }

    res.json({ deleted: true });
  } catch (error) {
    next(error);
  }
});

// Remove expired sessions and old throttling records.
const cleanupTimer = setInterval(async () => {
  try {
    if (pool) {
      await pool.query(
        "DELETE FROM botnest_sessions WHERE expires_at <= NOW()"
      );
    }

    const cutoff = Date.now() - LOGIN_WINDOW_MS;

    for (const [key, entry] of loginAttempts.entries()) {
      if (entry.startedAt < cutoff) {
        loginAttempts.delete(key);
      }
    }

    // Prevent the in-memory map from growing without bound.
    if (loginAttempts.size > MAX_ACTIVE_SESSIONS) {
      loginAttempts.clear();
    }
  } catch {
    console.error("Background cleanup failed.");
  }
}, 15 * 60 * 1000);

cleanupTimer.unref();

app.use((req, res) => {
  res.status(404).json({
    error: "API route not found."
  });
});

app.use((error, req, res, next) => {
  // Never log passwords, tokens, request bodies, or database URLs.
  console.error("BotNest API request failed:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "BotNest API error. Check the Render logs."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BotNest API listening on port ${PORT}`);
});
