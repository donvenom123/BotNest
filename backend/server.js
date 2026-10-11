
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: "https://donvenom123.github.io",
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Workspace-ID"
  ]
}));

app.use(express.json({ limit: "1mb" }));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

let tableReady;

async function ensureTable() {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured.");
  }

  if (!tableReady) {
    tableReady = pool.query(`
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
    `).catch(error => {
      tableReady = null;
      throw error;
    });
  }

  await tableReady;
}

function getWorkspace(req, res) {
  const id = req.get("X-Workspace-ID");

  if (!id || !/^[a-zA-Z0-9_-]{8,100}$/.test(id)) {
    res.status(400).json({
      error: "A valid workspace ID is required."
    });
    return null;
  }

  return id;
}

function normalizeChecks(value) {
  if (!Array.isArray(value)) {
    return [false, false, false, false];
  }

  return [0, 1, 2, 3].map(i => Boolean(value[i]));
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
    console.error("Database health check:", error.message);

    res.status(503).json({
      status: "error",
      database: "unavailable"
    });
  }
});

// List projects for this workspace
app.get("/api/projects", async (req, res, next) => {
  try {
    const workspaceId = getWorkspace(req, res);
    if (!workspaceId) return;

    await ensureTable();

    const result = await pool.query(
      `SELECT * FROM botnest_projects
       WHERE workspace_id = $1
       ORDER BY created_at DESC`,
      [workspaceId]
    );

    res.json({
      projects: result.rows.map(formatProject)
    });
  } catch (error) {
    next(error);
  }
});

// Create a project
app.post("/api/projects", async (req, res, next) => {
  try {
    const workspaceId = getWorkspace(req, res);
    if (!workspaceId) return;

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
        workspaceId,
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

// Update a project
app.patch("/api/projects/:id", async (req, res, next) => {
  try {
    const workspaceId = getWorkspace(req, res);
    if (!workspaceId) return;

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
        workspaceId
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

// Delete a project
app.delete("/api/projects/:id", async (req, res, next) => {
  try {
    const workspaceId = getWorkspace(req, res);
    if (!workspaceId) return;

    await ensureTable();

    const result = await pool.query(
      `DELETE FROM botnest_projects
       WHERE id = $1 AND workspace_id = $2`,
      [req.params.id, workspaceId]
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

app.use((error, req, res, next) => {
  console.error("BotNest API error:", error.message);

  res.status(500).json({
    error: "BotNest API error. Check the Render logs."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BotNest API listening on port ${PORT}`);
});
