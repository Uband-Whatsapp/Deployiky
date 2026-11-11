const API = "https://api.vercel.com";
const HISTORY_KEY = "ekkvm:history:v1";
const COOKIE = "ekkvm_session";
const SESSION_TTL = 43200;

class HttpError extends Error {
  constructor(message, status = 500) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(v => v.trim())
    .find(v => v.startsWith(COOKIE + "="));
  return item ? item.slice(COOKIE.length + 1) : "";
}

function base64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function createSession(password) {
  const expiry = Date.now() + SESSION_TTL * 1000;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(expiry))
  );
  return expiry + "." + base64url(signature);
}

async function verifySession(request, password) {
  if (!password) return false;
  try {
    const token = getCookie(request);
    const [expiryText, signatureText] = token.split(".");
    const expiry = Number(expiryText);
    if (!expiry || expiry <= Date.now() || !signatureText) return false;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64url(signatureText),
      new TextEncoder().encode(String(expiry))
    );
  } catch {
    return false;
  }
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    throw new HttpError("Format JSON tidak valid.", 400);
  }
}

async function saveHistory(env, item) {
  try {
    const old = await env.HISTORY.get(HISTORY_KEY, "json");
    const history = Array.isArray(old) ? old : [];
    history.unshift({
      id: crypto.randomUUID(),
      at: Date.now(),
      ...item
    });
    await env.HISTORY.put(
      HISTORY_KEY,
      JSON.stringify(history.slice(0, 300))
    );
  } catch (error) {
    console.error("History error:", error.message);
  }
}

async function vercel(path, env, options = {}) {
  const token = env.VERCEL_TOKEN;
  if (!token) {
    throw new HttpError(
      "VERCEL_TOKEN belum dipasang di Cloudflare Secrets.",
      500
    );
  }
  const url = new URL(API + path);
  if (env.VERCEL_TEAM_ID) {
    url.searchParams.set("teamId", env.VERCEL_TEAM_ID);
  }
  const response = await fetch(url.toString(), {
    method: options.method || "GET",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const raw = await response.text();
  let data = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { message: raw };
  }
  if (!response.ok) {
    const message =
      data?.error?.message ||
      data?.message ||
      "Vercel API gagal. HTTP " + response.status;
    throw new HttpError(message, response.status);
  }
  return data;
}

async function getProject(env, id) {
  if (!id) throw new HttpError("Project ID tidak ditemukan.", 400);
  const data = await vercel("/v9/projects/" + encodeURIComponent(id), env);
  return data.project || data;
}

async function getDeployments(env, projectId) {
  const params = new URLSearchParams({ limit: "100" });
  if (projectId) params.set("projectId", projectId);
  const data = await vercel("/v7/deployments?" + params.toString(), env);
  return (data.deployments || []).map(d => ({
    id: d.uid || d.id,
    name: d.name || "",
    url: d.url || "",
    state: d.readyState || d.state || "UNKNOWN",
    target: d.target || "preview",
    createdAt: Number(d.createdAt || d.created || 0),
    branch:
      d.meta?.githubCommitRef ||
      d.meta?.gitlabCommitRef ||
      d.gitSource?.ref ||
      "",
    inspectorUrl: d.inspectorUrl || "",
    errorMessage: d.errorMessage || ""
  }));
}

function deploymentResponse(d) {
  return {
    id: d.id || "",
    url: d.url
      ? (d.url.startsWith("http") ? d.url : "https://" + d.url)
      : "",
    state: d.readyState || d.state || "QUEUED",
    inspectorUrl: d.inspectorUrl || ""
  };
}

/* ============================================================
   PERBAIKAN: Upload file ke endpoint yang benar (/v2/now/files)
   ============================================================ */
async function uploadFileToVercel(env, fileName, buffer) {
  // Hitung SHA-1 digest (wajib untuk Vercel)
  const digest = await crypto.subtle.digest("SHA-1", buffer);
  const sha1 = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const token = env.VERCEL_TOKEN;
  // PERBAIKAN: Gunakan /v2/now/files, bukan /v2/files
  const url = new URL(API + "/v2/now/files");
  if (env.VERCEL_TEAM_ID) {
    url.searchParams.set("teamId", env.VERCEL_TEAM_ID);
  }

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/octet-stream",
      "x-vercel-digest": sha1
    },
    body: buffer
  });

  if (!response.ok) {
    const text = await response.text();
    throw new HttpError(
      "Upload file " + fileName + " gagal (HTTP " + response.status + "): " + text,
      response.status
    );
  }
  return sha1;
}

async function handleAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!sameOrigin(request)) {
    return json({ error: "Origin tidak diizinkan." }, 403);
  }
  if (!env.HISTORY) {
    return json({ error: "KV binding HISTORY belum dipasang." }, 500);
  }

  // ===========================
  // LOGIN
  // ===========================
  if (path === "/api/login" && method === "POST") {
    const password = env.ADMIN_PASSWORD;
    if (!password) {
      return json({
        error: "ADMIN_PASSWORD belum dipasang di Cloudflare Secrets."
      }, 500);
    }
    const body = await readBody(request);
    if (typeof body.password !== "string" || body.password !== password) {
      return json({ error: "Password admin salah." }, 401);
    }
    const session = await createSession(password);
    return json({ success: true }, 200, {
      "Set-Cookie":
        COOKIE + "=" + session +
        "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" +
        SESSION_TTL
    });
  }

  // ===========================
  // SESSION CHECK
  // ===========================
  if (path === "/api/session" && method === "GET") {
    const valid = await verifySession(request, env.ADMIN_PASSWORD);
    return valid
      ? json({ authenticated: true })
      : json({ error: "Belum login." }, 401);
  }

  // ===========================
  // LOGOUT
  // ===========================
  if (path === "/api/logout" && method === "POST") {
    return json({ success: true }, 200, {
      "Set-Cookie":
        COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
    });
  }

  // Auth gate untuk endpoint lain
  if (!(await verifySession(request, env.ADMIN_PASSWORD))) {
    return json({ error: "Sesi login tidak valid." }, 401);
  }

  try {
    // ===========================
    // LIST PROJECTS
    // ===========================
    if (path === "/api/projects" && method === "GET") {
      const data = await vercel("/v10/projects?limit=100", env);
      const result = (data.projects || []).map(p => {
        const link = p.link || {};
        return {
          id: p.id,
          name: p.name,
          framework: p.framework || "-",
          repository: link.org && link.repo ? link.org + "/" + link.repo : "",
          branch: link.productionBranch || "main",
          canDeploy:
            link.type === "github" &&
            Boolean(link.repoId || (link.org && link.repo))
        };
      });
      return json({ projects: result });
    }

    // ===========================
    // LIST DEPLOYMENTS
    // ===========================
    if (path === "/api/deployments" && method === "GET") {
      const projectId = url.searchParams.get("projectId");
      if (!projectId) throw new HttpError("Project ID diperlukan.", 400);
      const deployments = await getDeployments(env, projectId);
      return json({ deployments });
    }

    // ===========================
    // HISTORY
    // ===========================
    if (path === "/api/history" && method === "GET") {
      const stored = await env.HISTORY.get(HISTORY_KEY, "json") || [];
      let remote = [];
      try {
        remote = await getDeployments(env);
      } catch (error) {
        console.error("Vercel history error:", error.message);
      }
      const remoteHistory = remote.map(d => ({
        id: "vercel-" + d.id,
        deploymentId: d.id,
        at: d.createdAt || Date.now(),
        action: "Deployment Vercel",
        title: d.name || "Proyek",
        detail:
          (d.target || "preview") +
          (d.branch ? " · Branch " + d.branch : "") +
          (d.errorMessage ? " · " + d.errorMessage : ""),
        status: d.state,
        url: d.url ? "https://" + d.url : ""
      }));
      const remoteIds = new Set(remoteHistory.map(x => x.deploymentId));
      const localHistory = (Array.isArray(stored) ? stored : [])
        .filter(x => !x.deploymentId || !remoteIds.has(x.deploymentId));
      const history = [...remoteHistory, ...localHistory]
        .sort((a, b) => Number(b.at) - Number(a.at))
        .slice(0, 200);
      return json({ history });
    }

    // ===========================
    // RENAME PROJECT
    // ===========================
    if (path === "/api/rename" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);
      const name = String(body.name || "").trim();
      if (!name || name.length > 100 || !/^[a-zA-Z0-9._-]+$/.test(name)) {
        throw new HttpError(
          "Nama proyek tidak valid. Gunakan huruf, angka, titik, strip, atau underscore.",
          400
        );
      }
      try {
        const result = await vercel(
          "/v9/projects/" + encodeURIComponent(project.id),
          env,
          { method: "PATCH", body: { name } }
        );
        await saveHistory(env, {
          action: "Rename",
          title: project.name,
          detail: "Nama proyek menjadi " + name,
          status: "SUCCESS"
        });
        return json({ success: true, project: result.project || result });
      } catch (error) {
        await saveHistory(env, {
          action: "Rename",
          title: project.name,
          detail: error.message,
          status: "ERROR"
        });
        throw error;
      }
    }

    // ===========================
    // DELETE PROJECT
    // ===========================
    if (path === "/api/delete" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);
      if (body.confirmName !== project.name) {
        throw new HttpError("Nama konfirmasi tidak cocok.", 400);
      }
      try {
        await vercel(
          "/v9/projects/" + encodeURIComponent(project.id),
          env,
          { method: "DELETE" }
        );
        await saveHistory(env, {
          action: "Delete",
          title: project.name,
          detail: "Proyek berhasil dihapus.",
          status: "SUCCESS"
        });
        return json({ success: true });
      } catch (error) {
        await saveHistory(env, {
          action: "Delete",
          title: project.name,
          detail: error.message,
          status: "ERROR"
        });
        throw error;
      }
    }

    // ===========================
    // DEPLOY FROM GITHUB
    // ===========================
    if (path === "/api/deploy" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);
      const branch = String(body.branch || "").trim();
      const target = body.target === "production" ? "production" : "preview";
      if (!branch || branch.length > 200) {
        throw new HttpError("Branch tidak valid.", 400);
      }
      const link = project.link || {};
      if (link.type !== "github") {
        throw new HttpError(
          "Proyek belum menggunakan GitHub Integration.",
          400
        );
      }
      const gitSource = { type: "github", ref: branch };
      if (link.repoId) {
        gitSource.repoId = link.repoId;
      } else if (link.org && link.repo) {
        gitSource.org = link.org;
        gitSource.repo = link.repo;
      } else {
        throw new HttpError(
          "Informasi repository GitHub tidak ditemukan.",
          400
        );
      }
      const payload = {
        name: project.name,
        project: project.id,
        gitSource
      };
      if (target === "production") payload.target = "production";
      try {
        const result = await vercel(
          "/v13/deployments?forceNew=1",
          env,
          { method: "POST", body: payload }
        );
        await saveHistory(env, {
          action: "Deploy",
          title: project.name,
          detail: "Branch " + branch + " · " + target,
          deploymentId: result.id,
          status: result.readyState || "QUEUED",
          url: result.url ? "https://" + result.url : ""
        });
        return json({
          success: true,
          deployment: deploymentResponse(result)
        });
      } catch (error) {
        await saveHistory(env, {
          action: "Deploy",
          title: project.name,
          detail: "Branch " + branch + " · " + error.message,
          status: "ERROR"
        });
        throw error;
      }
    }

    // ============================================================
    // DEPLOY DARI FILE UPLOAD (multipart/form-data)
    // ============================================================
    if (path === "/api/deploy-files" && method === "POST") {
      const contentType = request.headers.get("Content-Type") || "";
      if (!contentType.includes("multipart/form-data")) {
        throw new HttpError("Format request harus multipart/form-data.", 400);
      }

      let formData;
      try {
        formData = await request.formData();
      } catch {
        throw new HttpError("Gagal membaca form data.", 400);
      }

      const name = String(formData.get("name") || "").trim();
      const projectId = String(formData.get("projectId") || "").trim();
      const target = formData.get("target") === "production"
        ? "production"
        : "preview";
      const fileEntries = formData.getAll("files");

      if (!name || name.length > 100 || !/^[a-zA-Z0-9._-]+$/.test(name)) {
        throw new HttpError(
          "Nama proyek tidak valid. Gunakan huruf, angka, titik, strip, atau underscore (maks 100 karakter).",
          400
        );
      }
      if (!fileEntries.length) {
        throw new HttpError("Tidak ada file yang diunggah.", 400);
      }

      const vercelFiles = [];
      let totalSize = 0;
      const MAX_TOTAL = 50 * 1024 * 1024; // 50MB

      for (const entry of fileEntries) {
        if (typeof entry === "string") continue;
        const fileName = String(entry.name || "file").replace(/^\/+/, "");
        if (!fileName) continue;

        const buffer = await entry.arrayBuffer();
        totalSize += buffer.byteLength;
        if (totalSize > MAX_TOTAL) {
          throw new HttpError(
            "Total ukuran file melebihi 50MB. Upload lebih sedikit file atau gunakan mode GitHub.",
            400
          );
        }

        // Upload file binary ke Vercel API, dapatkan SHA
        const sha = await uploadFileToVercel(env, fileName, buffer);
        vercelFiles.push({
          file: fileName,
          sha: sha,
          size: buffer.byteLength
        });
      }

      if (!vercelFiles.length) {
        throw new HttpError("File tidak valid.", 400);
      }

      const payload = {
        name,
        files: vercelFiles,
        target,
        projectSettings: {
          framework: null // Mencegah auto-detect framework yang minta konfirmasi
        }
      };
      if (projectId) payload.project = projectId;

      try {
        const result = await vercel(
          "/v13/deployments",
          env,
          { method: "POST", body: payload }
        );
        await saveHistory(env, {
          action: "Deploy Files",
          title: name,
          detail: vercelFiles.length + " file · " + target,
          deploymentId: result.id,
          status: result.readyState || "QUEUED",
          url: result.url ? "https://" + result.url : ""
        });
        return json({
          success: true,
          deployment: deploymentResponse(result)
        });
      } catch (error) {
        await saveHistory(env, {
          action: "Deploy Files",
          title: name,
          detail: error.message,
          status: "ERROR"
        });
        throw error;
      }
    }

    // ===========================
    // REDEPLOY LATEST
    // ===========================
    if (path === "/api/redeploy" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);
      const deployments = await getDeployments(env, project.id);
      deployments.sort(
        (a, b) => Number(b.createdAt) - Number(a.createdAt)
      );
      const latest = deployments[0];
      if (!latest || !latest.id) {
        throw new HttpError(
          "Belum ada deployment untuk di-redeploy.",
          404
        );
      }
      try {
        const result = await vercel(
          "/v13/deployments?forceNew=1",
          env,
          {
            method: "POST",
            body: { deploymentId: latest.id, withLatestCommit: true }
          }
        );
        await saveHistory(env, {
          action: "Redeploy",
          title: project.name,
          detail: "Mengulang deployment terbaru.",
          deploymentId: result.id,
          status: result.readyState || "QUEUED",
          url: result.url ? "https://" + result.url : ""
        });
        return json({
          success: true,
          deployment: deploymentResponse(result)
        });
      } catch (error) {
        await saveHistory(env, {
          action: "Redeploy",
          title: project.name,
          detail: error.message,
          status: "ERROR"
        });
        throw error;
      }
    }

    return json({ error: "Endpoint tidak ditemukan." }, 404);

  } catch (error) {
    console.error("API error:", error);
    return json(
      { error: error.message || "Terjadi kesalahan server." },
      error.status || 500
    );
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return handleAPI(request, env);
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("Asset binding ASSETS belum dipasang.", { status: 500 });
  }
};