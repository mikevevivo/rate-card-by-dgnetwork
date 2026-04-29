const assert = require("node:assert/strict");

const API_KEY = "AIzaSyAxSGf24Uf23tmXrBh_zX3aezL5GmUMFsE";

function getEnv(name, fallback) {
  const v = process.env[name];
  return (v === undefined || v === null || v === "") ? fallback : v;
}

function hostFromEnv(name, fallbackHost) {
  const v = getEnv(name, "");
  if (!v) return fallbackHost;
  return v.startsWith("http://") || v.startsWith("https://") ? new URL(v).host : v;
}

async function postJson(url, body, headers) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(headers || {}) },
    body: JSON.stringify(body || {}),
  });
  const text = await r.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  if (!r.ok) {
    const err = new Error(`HTTP ${r.status} ${url}: ${text || "<empty>"}`);
    err.status = r.status;
    err.body = text;
    throw err;
  }
  return json;
}

async function getJson(url, headers) {
  const r = await fetch(url, { method: "GET", headers: { ...(headers || {}) } });
  const text = await r.text();
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}: ${text || "<empty>"}`);
  return text ? JSON.parse(text) : null;
}

function parseOobCodeFromLink(resetLink) {
  const u = new URL(resetLink);
  const code = u.searchParams.get("oobCode");
  if (!code) throw new Error(`Missing oobCode in resetLink: ${resetLink}`);
  return code;
}

async function main() {
  const projectId = getEnv("GCLOUD_PROJECT", "rate-card-by-dgnetwork");
  const authHost = hostFromEnv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099");
  const functionsHost = hostFromEnv("FIREBASE_FUNCTIONS_EMULATOR_HOST", "127.0.0.1:5001");

  const authBase = `http://${authHost}/identitytoolkit.googleapis.com/v1`;
  const adminApiBase = `http://${functionsHost}/${projectId}/us-central1/adminApi`;

  const nonce = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const adminEmail = `mike@vevivo.com`;
  const invitedEmail = `invited+${nonce}@example.com`;
  const invitedPassword = `Invited-${nonce}-Pass!`;

  const authz = { "X-Emulator-Admin-Email": adminEmail };

  const inviteResult = await postJson(`${adminApiBase}/invite`, { email: invitedEmail }, authz);
  assert.equal(inviteResult.ok, true);
  assert.equal(inviteResult.email, invitedEmail);

  assert.ok(inviteResult.resetLink, "Expected resetLink");

  const invites1 = await getJson(`${adminApiBase}/invites`, authz);
  assert.ok(Array.isArray(invites1.invites), "Expected invites array");
  assert.ok(invites1.invites.some((i) => (i.email || "").toLowerCase() === invitedEmail), "Invited email not found in pending invites");

  const oobCode = parseOobCodeFromLink(inviteResult.resetLink);

  await postJson(`${authBase}/accounts:resetPassword?key=${API_KEY}`, {
    oobCode,
    newPassword: invitedPassword,
    returnSecureToken: true,
  });

  const invitedSignIn = await postJson(`${authBase}/accounts:signInWithPassword?key=${API_KEY}`, {
    email: invitedEmail,
    password: invitedPassword,
    returnSecureToken: true,
  });
  assert.ok(invitedSignIn && invitedSignIn.idToken, "Invited signIn did not return idToken");

  const invites2 = await getJson(`${adminApiBase}/invites`, authz);
  assert.ok(Array.isArray(invites2.invites), "Expected invites array");
  const stillPending = invites2.invites.some((i) => (i.email || "").toLowerCase() === invitedEmail);

  const users = await getJson(`${adminApiBase}/users`, authz);
  assert.ok(Array.isArray(users.users), "Expected users array");
  const invitedUser = users.users.find((u) => (u.email || "").toLowerCase() === invitedEmail);
  assert.ok(invitedUser, "Invited user not present in users list");

  process.stdout.write(
    JSON.stringify(
      {
        ok: true,
        projectId,
        adminEmail,
        invitedEmail,
        stillPending,
      },
      null,
      2
    ) + "\n"
  );
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + "\n");
  process.exitCode = 1;
});

