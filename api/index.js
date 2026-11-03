const { Redis } = require("@upstash/redis");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const redis = Redis.fromEnv();
const ORIGIN = process.env.ALLOWED_ORIGIN || "https://elementary-app.github.io";

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  if (req.method === "OPTIONS") return res.status(204).end();

  const action = req.query.a;
  const body = req.body || {};

  try {
    if (action === "signup" || action === "login") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) {
        return res.status(400).json({ error: "Use a valid email and a password of 8+ characters." });
      }
      const key = "user:" + email;
      const user = await redis.get(key);
      if (action === "signup") {
        if (user) return res.status(409).json({ error: "That email already has an account. Log in instead." });
        await redis.set(key, { hash: await bcrypt.hash(password, 10) });
      } else if (!user || !(await bcrypt.compare(password, user.hash))) {
        return res.status(401).json({ error: "Wrong email or password." });
      }
      const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "30d" });
      return res.json({ token, email });
    }

    if (action === "data") {
      let email;
      try {
        email = jwt.verify((req.headers.authorization || "").slice(7), process.env.JWT_SECRET).email;
      } catch (e) {
        return res.status(401).json({ error: "Please log in again." });
      }
      const key = "data:" + email;
      if (req.method === "PUT") {
        if (JSON.stringify(body).length > 200000) return res.status(413).json({ error: "Too large." });
        await redis.set(key, body);
        return res.json({ ok: true });
      }
      return res.json({ data: (await redis.get(key)) || null });
    }

    return res.status(404).json({ error: "Not found" });
  } catch (e) {
    return res.status(500).json({ error: "Server error." });
  }
};
