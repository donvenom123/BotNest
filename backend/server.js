const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/", (req, res) => {
res.json({
name: "BotNest API",
status: "online",
message: "BotNest backend is running"
});
});

app.get("/health", (req, res) => {
res.json({ status: "ok" });
});

app.listen(PORT, "0.0.0.0", () => {
console.log("BotNest API listening on port ${PORT}");
});