const express = require("express");
const crypto = require("node:crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
app.use(express.json({ limit: "2kb" }));

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.get("/", (req, res) => {
  res.status(200).send("Hibuz Installer Auth API is running");
});

app.post("/verify", verifyLimiter, (req, res) => {
  const configuredPassword = process.env.INSTALL_PASSWORD;
  const submittedPassword = req.body?.password;

  if (!configuredPassword) {
    return res.status(503).json({
      valid: false,
      message: "Verification service is not configured"
    });
  }

  if (typeof submittedPassword !== "string") {
    return res.status(400).json({
      valid: false,
      message: "Password is required"
    });
  }

  const expected = Buffer.from(configuredPassword, "utf8");
  const received = Buffer.from(submittedPassword, "utf8");

  const valid =
    expected.length === received.length &&
    crypto.timingSafeEqual(expected, received);

  if (!valid) {
    return res.status(401).json({
      valid: false,
      message: "Invalid installation password"
    });
  }

  return res.status(200).json({
    valid: true,
    message: "Password verified"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Hibuz Installer Auth API listening on ${PORT}`);
});