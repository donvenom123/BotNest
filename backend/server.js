
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_ORIGIN = "https://donvenom123.github.io";
const SESSION_HOURS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

const OWNER_EMAIL = (process.env.BOTNEST_OWNER_EMAIL || "")
  .trim()
  .toLowerCase();

const OWNER_PASSWORD = process.env.BOTNEST_OWNER_PASSWORD || "";
const OWNER_WORKSPACE_ID =
  process.env.BOTNEST_OWNER_WORKSPACE_ID || "";

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5
    })
  : null;

app.disable("x-powered-by");

app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "1mb" }));

// Basic in-memory login throttling.
// Attempts reset if the service restarts.
const loginAttempts = new Map();

function getClientKey(req) {
  // Do not trust forwarded IP headers unless the proxy setup
  // is explicitly configured to do so.
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
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeEqualStrings(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  if (left.length !== right.length) {
    // Still perform a comparison to reduce obvious timing differences.
    crypto.timingSafeEqual(
      crypto.createHash("sha256").update(left).digest(),
      crypto.createHash("sha256").update(right).digest()
    );
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function validOwnerConfiguration() {
  return Boolean(
    OWNER_EMAIL &&
    OWNER_PASSWORD.length >= 16 &&
    /^[a-zA-Z0-9_-]{8,100}$/.test(OWNER_WORKSPACE_ID)
  );
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
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          expires_at TIMESTAMPTZ NOT NULL
        );

        CREATE INDEX IF NOT EXISTS botnest_sessions_expiry_idx
        ON botnest_sessions (expires_at);

        CREATE TABLE IF NOT EXISTS botnest_settings (
          setting_key TEXT PRIMARY KEY,
          setting_value TEXT NOT NULL
        );
      `);
    })().catch(error => {
      tableReady = null;
      throw error;
    });
  }

  await tableReady;
}

// This app is owner-only for now. On the first successful owner login,
// consolidate existing projects into the configured owner workspace.
// This preserves project IDs and contents. It assumes all existing
// projects in this database belong to this owner.
async function migrateProjectsToOwnerWorkspace() {
  const settingKey = "owner_workspace_migration_v1";

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const existing = await client.query(
      `SELECT setting_value
       FROM botnest_settings
       WHERE setting_key = $1
       FOR UPDATE`,
      [settingKey]
    );

    if (!existing.rowCount) {
      await client.query(
        `UPDATE botnest_projects
         SET workspace_id = $1,
             updated_at = NOW()
         WHERE workspace_id <> $1`,
        [OWNER_WORKSPACE_ID]
      );

      await client.query(
        `INSERT INTO botnest_settings (setting_key, setting_value)
         VALUES ($1, $2)`,
        [settingKey, "complete"]
      );
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
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
    checks: row.checks,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function authenticate(req, res, next) {
  try {
    const header = req.get("Authorization") || "";
    const match = header.match(/^Bearer ([A-Za-z0-9_-]{40,200})$/);

    if (!match) {
      return res.status(401).json({
        error: "Please sign in to BotNest."
      });
    }

    await ensureTable();

    const tokenHash = sha256(match[1]);

    const result = await pool.query(
      `SELECT token_hash
       FROM botnest_sessions
       WHERE token_hash = $1
         AND expires_at > NOW()`,
      [tokenHash]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Session expired. Please sign in again."
      });
    }

    req.ownerWorkspaceId = OWNER_WORKSPACE_ID;
    req.sessionTokenHash = tokenHash;

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
        database: "not_configured"
      });
    }

    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      service: "BotNest API",
      database: "connected"
    });
  } catch (error) {
    console.error("Database health check failed.");

    res.status(503).json({
      status: "error",
      database: "unavailable"
    });
  }
});

// Check whether owner authentication is configured.
// This endpoint never returns the configured email or password.
app.get("/api/auth/status", (req, res) => {
  res.json({
    configured: validOwnerConfiguration(),
    registration: "disabled"
  });
});

// Owner-only login. There is no public registration endpoint.
app.post("/api/auth/login", async (req, res, next) => {
  const key = getClientKey(req);

  try {
    if (isRateLimited(key)) {
      return res.status(429).json({
        error: "Too many login attempts. Try again later."
      });
    }

    if (!validOwnerConfiguration()) {
      return res.status(503).json({
        error: "Owner authentication is not configured correctly."
      });
    }

    const email = typeof req.body?.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";

    const password = typeof req.body?.password === "string"
      ? req.body.password
      : "";

    const emailOK = safeEqualStrings(email, OWNER_EMAIL);
    const passwordOK = safeEqualStrings(password, OWNER_PASSWORD);

    if (!emailOK || !passwordOK) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    await ensureTable();
    await migrateProjectsToOwnerWorkspace();

    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = sha256(token);

    await pool.query(
      `INSERT INTO botnest_sessions (token_hash, expires_at)
       VALUES ($1, NOW() + INTERVAL '${SESSION_HOURS} hours')`,
      [tokenHash]
    );

    clearLoginAttempts(key);

    res.set("Cache-Control", "no-store");
    res.json({
      token,
      expiresInSeconds: SESSION_HOURS * 60 * 60,
      owner: true
    });
  } catch (error) {
    next(error);
  }
});

// Logout invalidates this session on the server.
app.post("/api/auth/logout", authenticate, async (req, res, next) => {
  try {
    await pool.query(
      "DELETE FROM botnest_sessions WHERE token_hash = $1",
      [req.sessionTokenHash]
    );

    res.json({ loggedOut: true });
  } catch (error) {
    next(error);
  }
});

// Session check for the dashboard.
app.get("/api/auth/me", authenticate, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ authenticated: true, owner: true });
});

// All project routes now require a valid owner session.
// Workspace identity comes from server configuration, not a request header.

app.get("/api/projects", authenticate, async (req, res, next) => {
  try {
    await ensureTable();

    const result = await pool.query(
      `SELECT * FROM botnest_projects
       WHERE workspace_id = $1
       ORDER BY created_at DESC`,
      [req.ownerWorkspaceId]
    );

    res.set("Cache-Control", "no-store");
    res.json({ projects: result.rows.map(formatProject) });
  } catch (error) {
    next(error);
  }
});

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

    await ensureTable();

    const result = await pool.query(
      `INSERT INTO botnest_projects
       (id, workspace_id, name, platform, checks)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       RETURNING *`,
      [
        crypto.randomUUID(),
        req.ownerWorkspaceId,
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

app.patch("/api/projects/:id", authenticate, async (req, res, next) => {
  try {
    const { name, platform, checks } = req.body || {};

    if (
      name !== undefined &&
      (typeof name !== "string" ||
       !name.trim() ||
       name.trim().length > 100)
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

    await ensureTable();

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
        req.ownerWorkspaceId
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Project not found."
      });
    }

    res.json({ project: formatProject(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/projects/:id", authenticate, async (req, res, next) => {
  try {
    await ensureTable();

    const result = await pool.query(
      `DELETE FROM botnest_projects
       WHERE id = $1 AND workspace_id = $2`,
      [req.params.id, req.ownerWorkspaceId]
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

// Periodically remove expired sessions and stale login throttling entries.
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
  } catch {
    console.error("Background cleanup failed.");
  }
}, 15 * 60 * 1000);

cleanupTimer.unref();

app.use((error, req, res, next) => {
  // Do not log request bodies, passwords, tokens, or database URLs.
  console.error("BotNest API request failed:", error.message);

  res.status(500).json({
    error: "BotNest API error. Check the Render logs."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BotNest API listening on port ${PORT}`);
});
