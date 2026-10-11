
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  "https://donvenom123.github.io"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "1mb" }));

// Temporary storage.
// Projects will reset when this server restarts.
// PostgreSQL will be needed for permanent storage.
const projects = new Map();

app.get("/", (req, res) => {
  res.json({
    name: "BotNest API",
    status: "online",
    platforms: ["discord", "telegram", "whatsapp"],
    message: "BotNest backend is running"
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "BotNest API"
  });
});

// Create a bot project
app.post("/api/projects", (req, res) => {
  const { name, platform } = req.body || {};

  if (
    typeof name !== "string" ||
    !name.trim() ||
    name.trim().length > 100
  ) {
    return res.status(400).json({
      error: "Enter a bot name"
    });
  }

  const supported = [
    "discord",
    "telegram",
    "whatsapp"
  ];

  if (!supported.includes(platform)) {
    return res.status(400).json({
      error: "Unsupported platform"
    });
  }

  const project = {
    id: crypto.randomUUID(),
    name: name.trim(),
    platform,
    status: "setup_required",
    createdAt: new Date().toISOString()
  };

  projects.set(project.id, project);

  res.status(201).json({
    message: "Project created",
    project
  });
});

// List saved projects
app.get("/api/projects", (req, res) => {
  res.json({
    projects: Array.from(projects.values())
  });
});

// Get one project
app.get("/api/projects/:id", (req, res) => {
  const project = projects.get(req.params.id);

  if (!project) {
    return res.status(404).json({
      error: "Project not found"
    });
  }

  res.json({ project });
});

// Update project name or status
app.patch("/api/projects/:id", (req, res) => {
  const project = projects.get(req.params.id);

  if (!project) {
    return res.status(404).json({
      error: "Project not found"
    });
  }

  const { name, status } = req.body || {};
  const allowedStatuses = [
    "setup_required",
    "stopped",
    "running",
    "error"
  ];

  if (name !== undefined) {
    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.trim().length > 100
    ) {
      return res.status(400).json({
        error: "Invalid project name"
      });
    }

    project.name = name.trim();
  }

  if (status !== undefined) {
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        error: "Invalid status"
      });
    }

    project.status = status;
  }

  project.updatedAt = new Date().toISOString();
  projects.set(project.id, project);

  res.json({ project });
});

// Delete a project
app.delete("/api/projects/:id", (req, res) => {
  if (!projects.has(req.params.id)) {
    return res.status(404).json({
      error: "Project not found"
    });
  }

  projects.delete(req.params.id);

  res.json({ deleted: true });
});

// WhatsApp webhook verification
app.get("/webhooks/whatsapp", (req, res) => {
  const verifyToken =
    process.env.WHATSAPP_VERIFY_TOKEN;

  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    verifyToken &&
    token === verifyToken
  ) {
    return res.status(200).send(String(challenge));
  }

  res.sendStatus(403);
});

// Receive WhatsApp webhook events.
// This receives events but does not yet reply to messages.
app.post("/webhooks/whatsapp", (req, res) => {
  if (
    req.body &&
    req.body.object === "whatsapp_business_account"
  ) {
    console.log("WhatsApp webhook received");
    return res.sendStatus(200);
  }

  res.sendStatus(404);
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.message);

  if (err.message === "Origin not allowed") {
    return res.status(403).json({
      error: "Origin not allowed"
    });
  }

  res.status(500).json({
    error: "Internal server error"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `BotNest API listening on port ${PORT}`
  );
});
