const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();

const ADMIN_EMAILS = new Set(["mike@vevivo.com", "tony@dgnetwork.eu"]);
const WEB_API_KEY = "AIzaSyAxSGf24Uf23tmXrBh_zX3aezL5GmUMFsE";

function setCors(req, res) {
  const origin = req.headers.origin;
  const allowed = new Set([
    "https://rate-card-by-dgnetwork.web.app",
    "https://rate-card-by-dgnetwork.firebaseapp.com",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
  ]);

  if (origin && allowed.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type");
}

async function requireAdmin(req, res) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) {
    res.status(401).json({ error: "UNAUTHENTICATED" });
    return null;
  }

  try {
    const decoded = await admin.auth().verifyIdToken(match[1]);
    const email = (decoded.email || "").toLowerCase();
    if (!email || !ADMIN_EMAILS.has(email)) {
      res.status(403).json({ error: "FORBIDDEN" });
      return null;
    }
    return decoded;
  } catch (e) {
    res.status(401).json({ error: "UNAUTHENTICATED" });
    return null;
  }
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

exports.adminApi = functions.https.onRequest(async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }

  const adminUser = await requireAdmin(req, res);
  if (!adminUser) return;

  const path = (req.path || "/").replace(/\/+$/, "") || "/";
  const parts = path.split("/").filter(Boolean);

  try {
    if (req.method === "GET" && (path === "/" || path === "/users")) {
      const max = Math.min(parseInt(req.query.max, 10) || 100, 1000);
      const nextPageToken = req.query.nextPageToken || undefined;
      const result = await admin.auth().listUsers(max, nextPageToken);
      res.json({
        users: result.users.map((u) => ({
          uid: u.uid,
          email: u.email || null,
          emailVerified: !!u.emailVerified,
          disabled: !!u.disabled,
          createdAt: u.metadata.creationTime || null,
          lastSignInAt: u.metadata.lastSignInTime || null,
        })),
        nextPageToken: result.pageToken || null,
      });
      return;
    }

    if (req.method === "POST" && path === "/invite") {
      const body = await readJsonBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      if (!email || !email.includes("@")) {
        res.status(400).json({ error: "INVALID_EMAIL" });
        return;
      }

      let created = false;
      try {
        await admin.auth().getUserByEmail(email);
      } catch (e) {
        if (e && e.code === "auth/user-not-found") {
          await admin.auth().createUser({ email });
          created = true;
        } else {
          throw e;
        }
      }

      const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${WEB_API_KEY}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requestType: "PASSWORD_RESET", email }),
      });

      if (!r.ok) {
        const text = await r.text();
        res.status(500).json({ error: "INVITE_FAILED", detail: text });
        return;
      }

      res.json({ ok: true, email, created });
      return;
    }

    if (req.method === "DELETE" && parts[0] === "users" && parts[1]) {
      const uid = decodeURIComponent(parts[1]);
      await admin.auth().deleteUser(uid);
      res.json({ ok: true, uid });
      return;
    }

    res.status(404).json({ error: "NOT_FOUND" });
  } catch (e) {
    res.status(500).json({ error: "INTERNAL", message: String(e && e.message ? e.message : e) });
  }
});
