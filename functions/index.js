const functions = require("firebase-functions");
const admin = require("firebase-admin");

function isEmulator() {
  return String(process.env.FUNCTIONS_EMULATOR || "").toLowerCase() === "true" || !!process.env.FIREBASE_AUTH_EMULATOR_HOST;
}

function getContinueUrl() {
  return process.env.APP_URL || "https://rate-card-by-dgnetwork.web.app/";
}

if (String(process.env.FUNCTIONS_EMULATOR || "").toLowerCase() === "true" && !process.env.FIREBASE_AUTH_EMULATOR_HOST) {
  process.env.FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099";
}

admin.initializeApp();

const ADMIN_EMAILS = new Set(["mike@vevivo.com", "tony@dgnetwork.eu"]);
const WEB_API_KEY = "AIzaSyAxSGf24Uf23tmXrBh_zX3aezL5GmUMFsE";
const db = admin.firestore();
const accessDoc = db.doc("config/access");

function httpError(httpStatus, publicError, message) {
  const err = new Error(message || publicError || "ERROR");
  err.httpStatus = httpStatus;
  err.publicError = publicError;
  return err;
}

function isFirestoreDisabledError(e) {
  const msg = String(e && e.message ? e.message : e || "");
  const code = e && (e.code || e.status);
  return (
    code === 7 ||
    code === "7" ||
    code === "permission-denied" ||
    /PERMISSION_DENIED/i.test(msg) ||
    /firestore\.googleapis\.com/i.test(msg)
  );
}

function normalizeDomain(input) {
  const v = String(input || "").trim().toLowerCase();
  const noAt = v.startsWith("@") ? v.slice(1) : v;
  const domain = noAt.replace(/\.+$/g, "");
  if (!domain) return null;
  if (domain.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  if (!domain.includes(".")) return null;
  if (domain.startsWith(".") || domain.endsWith(".")) return null;
  if (domain.includes("..")) return null;
  return domain;
}

function domainFromEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  const at = e.lastIndexOf("@");
  if (at < 0) return null;
  return normalizeDomain(e.slice(at + 1));
}

async function getAllowedDomains() {
  try {
    const snap = await accessDoc.get();
    const data = snap.exists ? snap.data() : null;
    const domains = data && Array.isArray(data.allowedDomains) ? data.allowedDomains : [];
    return domains
      .map((d) => normalizeDomain(d))
      .filter((d) => !!d);
  } catch (e) {
    if (isFirestoreDisabledError(e)) {
      throw httpError(
        503,
        "FIRESTORE_DISABLED",
        "Allowed domains are unavailable because Cloud Firestore is not enabled for this project. Enable Firestore (Firestore Database) in Firebase Console, or enable the Cloud Firestore API, then retry."
      );
    }
    throw e;
  }
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...(options || {}), signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("TIMEOUT")), timeoutMs)),
  ]);
}

function parseTimeMs(value) {
  if (!value) return null;
  const ms = Date.parse(String(value));
  return Number.isFinite(ms) ? ms : null;
}

function setCors(req, res) {
  const origin = req.headers.origin;
  const allowed = new Set([
    "https://rate-card-by-dgnetwork.web.app",
    "https://rate-card-by-dgnetwork.firebaseapp.com",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
  ]);

  const allowByPattern =
    typeof origin === "string" &&
    (origin === "null" ||
      /^https:\/\/rate-card-by-dgnetwork(?:--[a-z0-9-]+)?\.web\.app$/i.test(origin) ||
      /^https:\/\/rate-card-by-dgnetwork(?:--[a-z0-9-]+)?\.firebaseapp\.com$/i.test(origin) ||
      /^http:\/\/localhost(?::\d+)?$/i.test(origin) ||
      /^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(origin));

  if (origin && (allowed.has(origin) || allowByPattern)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Emulator-Admin-Email");
}

async function requireAdmin(req, res) {
  if (isEmulator()) {
    const emuEmail = String(req.headers["x-emulator-admin-email"] || "").toLowerCase();
    if (emuEmail && ADMIN_EMAILS.has(emuEmail)) return { email: emuEmail };
  }

  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) {
    res.status(401).json({ error: "UNAUTHENTICATED" });
    return null;
  }

  try {
    const decoded = isEmulator()
      ? await withTimeout(admin.auth().verifyIdToken(match[1]), 8000)
      : await admin.auth().verifyIdToken(match[1]);
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
  if (req && req.body) {
    if (typeof req.body === "object") return Promise.resolve(req.body);
    if (typeof req.body === "string" && req.body.trim()) {
      try {
        return Promise.resolve(JSON.parse(req.body));
      } catch (e) {
        return Promise.reject(e);
      }
    }
  }

  if (req && req.rawBody && req.rawBody.length) {
    try {
      return Promise.resolve(JSON.parse(Buffer.from(req.rawBody).toString("utf8")));
    } catch (e) {
      return Promise.reject(e);
    }
  }

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

async function getUserClaims(userRecord) {
  const claims = userRecord && userRecord.customClaims ? userRecord.customClaims : null;
  if (claims && typeof claims === "object") return claims;
  if (!userRecord || !userRecord.uid) return {};
  const full = isEmulator()
    ? await withTimeout(admin.auth().getUser(userRecord.uid), 12000)
    : await admin.auth().getUser(userRecord.uid);
  return full && full.customClaims && typeof full.customClaims === "object" ? full.customClaims : {};
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
      const claimsByUid = new Map();
      for (const u of result.users) {
        if (!u || !u.uid) continue;
        claimsByUid.set(u.uid, await getUserClaims(u));
      }
      res.json({
        users: result.users.map((u) => ({
          uid: u.uid,
          email: u.email || null,
          role:
            u.email && ADMIN_EMAILS.has(String(u.email).toLowerCase())
              ? "admin"
              : claimsByUid.get(u.uid) && typeof claimsByUid.get(u.uid).role === "string" && claimsByUid.get(u.uid).role.trim()
                ? claimsByUid.get(u.uid).role.trim()
                : "user",
          emailVerified: !!u.emailVerified,
          disabled: !!u.disabled,
          createdAt: u.metadata.creationTime || null,
          lastSignInAt: u.metadata.lastSignInTime || null,
          invited: !!(claimsByUid.get(u.uid) && claimsByUid.get(u.uid).invited),
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
      let userRecord = null;
      try {
        userRecord = await admin.auth().getUserByEmail(email);
      } catch (e) {
        if (e && e.code === "auth/user-not-found") {
          userRecord = await admin.auth().createUser({ email });
          created = true;
        } else {
          throw e;
        }
      }

      const prevClaims = (userRecord && userRecord.customClaims) ? userRecord.customClaims : {};
      const nextClaims = {
        ...prevClaims,
        invited: true,
        invitedAt: Date.now(),
        invitedBy: String(adminUser.email || "").toLowerCase(),
      };
      await admin.auth().setCustomUserClaims(userRecord.uid, nextClaims);

      const resetLink = await withTimeout(
        admin.auth().generatePasswordResetLink(email, {
          url: getContinueUrl(),
          handleCodeInApp: false,
        }),
        12000
      );
      res.json({ ok: true, email, created, resetLink });
      return;
    }

    if (req.method === "GET" && path === "/invites") {
      const max = Math.min(parseInt(req.query.max, 10) || 1000, 1000);
      const result = await admin.auth().listUsers(max);
      const pending = [];
      for (const u of result.users) {
        if (!u || !u.uid) continue;
        const claims = await getUserClaims(u);
        if (!claims || !claims.invited) continue;
        const lastSignInMs = parseTimeMs(u.metadata && u.metadata.lastSignInTime ? u.metadata.lastSignInTime : null);
        const invitedAtMs = typeof claims.invitedAt === "number" ? claims.invitedAt : parseInt(String(claims.invitedAt || "0"), 10) || 0;
        if (lastSignInMs && invitedAtMs && lastSignInMs >= invitedAtMs) continue;
        pending.push({
          uid: u.uid,
          email: u.email || null,
          createdAt: u.metadata.creationTime || null,
          invitedAt: claims.invitedAt || null,
          invitedBy: claims.invitedBy || null,
        });
      }
      pending.sort((a, b) => (b.invitedAt || 0) - (a.invitedAt || 0));
      res.json({ invites: pending });
      return;
    }

    if (req.method === "POST" && path === "/invites/link") {
      const body = await readJsonBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      if (!email || !email.includes("@")) {
        res.status(400).json({ error: "INVALID_EMAIL" });
        return;
      }

      let userRecord = null;
      try {
        userRecord = await admin.auth().getUserByEmail(email);
      } catch (e) {
        if (e && e.code === "auth/user-not-found") {
          userRecord = await admin.auth().createUser({ email });
        } else {
          throw e;
        }
      }

      const prevClaims = (userRecord && userRecord.customClaims) ? userRecord.customClaims : {};
      const nextClaims = {
        ...prevClaims,
        invited: true,
        invitedAt: Date.now(),
        invitedBy: String(adminUser.email || "").toLowerCase(),
      };
      await admin.auth().setCustomUserClaims(userRecord.uid, nextClaims);

      const resetLink = await withTimeout(
        admin.auth().generatePasswordResetLink(email, {
          url: getContinueUrl(),
          handleCodeInApp: false,
        }),
        12000
      );
      res.json({ ok: true, email, resetLink });
      return;
    }

    if (req.method === "GET" && path === "/allowed-domains") {
      const domains = await getAllowedDomains();
      res.json({ ok: true, domains });
      return;
    }

    if (req.method === "POST" && path === "/allowed-domains") {
      const body = await readJsonBody(req);
      const domain = normalizeDomain(body.domain);
      if (!domain) {
        res.status(400).json({ error: "INVALID_DOMAIN" });
        return;
      }

      try {
        await db.runTransaction(async (tx) => {
          const snap = await tx.get(accessDoc);
          const data = snap.exists ? snap.data() : {};
          const prev = Array.isArray(data.allowedDomains) ? data.allowedDomains : [];
          const next = new Set(prev.map((d) => normalizeDomain(d)).filter((d) => !!d));
          next.add(domain);
          tx.set(
            accessDoc,
            {
              allowedDomains: Array.from(next).sort(),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              updatedBy: String(adminUser.email || "").toLowerCase(),
            },
            { merge: true }
          );
        });
      } catch (e) {
        if (isFirestoreDisabledError(e)) {
          throw httpError(
            503,
            "FIRESTORE_DISABLED",
            "Cannot update allowed domains because Cloud Firestore is not enabled for this project. Enable Firestore (Firestore Database) in Firebase Console, or enable the Cloud Firestore API, then retry."
          );
        }
        throw e;
      }

      res.json({ ok: true, domain });
      return;
    }

    if (req.method === "DELETE" && parts[0] === "allowed-domains" && parts[1]) {
      const domain = normalizeDomain(decodeURIComponent(parts[1]));
      if (!domain) {
        res.status(400).json({ error: "INVALID_DOMAIN" });
        return;
      }

      try {
        await db.runTransaction(async (tx) => {
          const snap = await tx.get(accessDoc);
          const data = snap.exists ? snap.data() : {};
          const prev = Array.isArray(data.allowedDomains) ? data.allowedDomains : [];
          const next = prev.map((d) => normalizeDomain(d)).filter((d) => !!d && d !== domain);
          tx.set(
            accessDoc,
            {
              allowedDomains: Array.from(new Set(next)).sort(),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              updatedBy: String(adminUser.email || "").toLowerCase(),
            },
            { merge: true }
          );
        });
      } catch (e) {
        if (isFirestoreDisabledError(e)) {
          throw httpError(
            503,
            "FIRESTORE_DISABLED",
            "Cannot update allowed domains because Cloud Firestore is not enabled for this project. Enable Firestore (Firestore Database) in Firebase Console, or enable the Cloud Firestore API, then retry."
          );
        }
        throw e;
      }

      res.json({ ok: true, domain });
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
    const status = e && typeof e.httpStatus === "number" ? e.httpStatus : 500;
    const error = e && typeof e.publicError === "string" ? e.publicError : "INTERNAL";
    res.status(status).json({ error, message: String(e && e.message ? e.message : e) });
  }
});

exports.publicApi = functions.https.onRequest(async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }

  const path = (req.path || "/").replace(/\/+$/, "") || "/";

  try {
    if (req.method === "GET" && (path === "/" || path === "/allowed-domains")) {
      const domains = await getAllowedDomains();
      res.json({ ok: true, domains });
      return;
    }

    res.status(404).json({ error: "NOT_FOUND" });
  } catch (e) {
    const status = e && typeof e.httpStatus === "number" ? e.httpStatus : 500;
    const error = e && typeof e.publicError === "string" ? e.publicError : "INTERNAL";
    res.status(status).json({ error, message: String(e && e.message ? e.message : e) });
  }
});
