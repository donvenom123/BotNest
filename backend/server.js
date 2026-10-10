const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  "https://donvenom123.github.io"
];

// Allow requests from the BotNest dashboard
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    name: "BotNest API",
    status: "online",
    message: "BotNest backend is running"
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "BotNest API"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BotNest API listening on port ${PORT}`);
});