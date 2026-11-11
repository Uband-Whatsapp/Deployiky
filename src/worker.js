
const VERCEL_API = "https://api.vercel.com";
const HISTORY_KEY = "ekkvm:history";
const COOKIE_NAME = "ekkvm_session";
const SESSION_SECONDS = 43200;

class HttpError extends Error {
  constructor(message, status = 500) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });
}

function getSecret(env, upper, lower) {
  return env[upper] || env[lower] || "";
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const item = cookie.split(";").map(v => v.trim())
    .find(v => v.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : "";
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function validOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function saveHistory(env, item) {
  try {
    if (!env.HISTORY) return;

    const old = await env.HISTORY.get(HISTORY_KEY, "json");
    const list = Array.isArray(old) ? old : [];

    list.unshift({
      id: crypto.randomUUID(),
      at: Date.now(),
      ...item
    });

    await env.HISTORY.put(
      HISTORY_KEY,
      JSON.stringify(list.slice(0, 200))
    );
  } catch (error) {
    console.error("History error:", error.message);
  }
}

async function isLoggedIn(request, env) {
  if (!env.HISTORY) return false;

  const token = getCookie(request, COOKIE_NAME);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return false;

  const session = await env.HISTORY.get("session:" + token);
  return session === "active";
}

async function vercelFetch(path, env, options = {}) {
  const token = getSecret(env, "VERCEL_TOKEN", "vercel_token");

  if (!token) {
    throw new HttpError(
      "VERCEL_TOKEN belum dipasang di Cloudflare Worker Secrets.",
      500
    );
  }

  const url = new URL(VERCEL_API + path);
  const teamId = getSecret(env, "VERCEL_TEAM_ID", "vercel_team_id");

  if (teamId) url.searchParams.set("teamId", teamId);

  const response = await fetch(url.toString(), {
    method: options.method || "GET",
    headers: {
      "Authorization": "Bearer " + token,
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
      "Vercel API error (" + response.status + ")";

    throw new HttpError(message, response.status);
  }

  return data;
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    throw new HttpError("Format JSON tidak valid.", 400);
  }
}

async function getProject(env, id) {
  if (!id) throw new HttpError("Project ID tidak ditemukan.", 400);

  const data = await vercelFetch(
    "/v9/projects/" + encodeURIComponent(id),
    env
  );

  return data.project || data;
}

async function getDeployments(env, projectId) {
  if (!projectId) {
    throw new HttpError("Project ID tidak ditemukan.", 400);
  }

  const params = new URLSearchParams({
    projectId,
    limit: "30"
  });

  const data = await vercelFetch(
    "/v7/deployments?" + params.toString(),
    env
  );

  return (data.deployments || []).map(d => ({
    id: d.uid || d.id,
    name: d.name,
    url: d.url || "",
    state: d.readyState || d.state || "UNKNOWN",
    target: d.target || "",
    createdAt: d.createdAt || d.created || null,
    branch:
      d.meta?.githubCommitRef ||
      d.meta?.gitlabCommitRef ||
      d.gitSource?.ref ||
      "",
    inspectorUrl: d.inspectorUrl || "",
    errorMessage: d.errorMessage || ""
  }));
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!validOrigin(request)) {
    return json({ error: "Origin tidak diizinkan." }, 403);
  }

  if (!env.HISTORY) {
    return json({
      error: "KV belum terhubung. Pasang binding HISTORY ke namespace github-index-manager-history."
    }, 500);
  }

  // LOGIN
  if (path === "/api/login" && method === "POST") {
    const password = getSecret(env, "ADMIN_PASSWORD", "admin_password");

    if (!password) {
      return json({
        error: "ADMIN_PASSWORD belum dipasang di Worker Secrets."
      }, 500);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const failKey = "login-fail:" + ip;
    const failCount = Number(await env.HISTORY.get(failKey) || 0);

    if (failCount >= 8) {
      return json({
        error: "Terlalu banyak percobaan login. Coba lagi nanti."
      }, 429);
    }

    const body = await readBody(request);

    if (typeof body.password !== "string" || body.password !== password) {
      await env.HISTORY.put(
        failKey,
        String(failCount + 1),
        { expirationTtl: 900 }
      );

      return json({ error: "Password admin salah." }, 401);
    }

    await env.HISTORY.delete(failKey);

    const token = randomToken();

    await env.HISTORY.put(
      "session:" + token,
      "active",
      { expirationTtl: SESSION_SECONDS }
    );

    return json(
      { success: true },
      200,
      {
        "Set-Cookie":
          COOKIE_NAME + "=" + token +
          "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" +
          SESSION_SECONDS
      }
    );
  }

  // CEK SESSION
  if (path === "/api/session" && method === "GET") {
    const logged = await isLoggedIn(request, env);
    return logged
      ? json({ authenticated: true })
      : json({ error: "Belum login." }, 401);
  }

  // LOGOUT
  if (path === "/api/logout" && method === "POST") {
    const token = getCookie(request, COOKIE_NAME);

    if (token) {
      await env.HISTORY.delete("session:" + token);
    }

    return json(
      { success: true },
      200,
      {
        "Set-Cookie":
          COOKIE_NAME + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
      }
    );
  }

  // Semua route selanjutnya harus login
  if (!(await isLoggedIn(request, env))) {
    return json({ error: "Sesi login tidak valid." }, 401);
  }

  try {
    // LIST PROJECTS
    if (path === "/api/projects" && method === "GET") {
      const data = await vercelFetch("/v10/projects?limit=100", env);

      const result = (data.projects || []).map(p => {
        const link = p.link || {};
        const repo = [link.org, link.repo]
          .filter(Boolean).join("/");

        const canDeploy =
          link.type === "github" &&
          Boolean(link.repoId || (link.org && link.repo));

        return {
          id: p.id,
          name: p.name,
          framework: p.framework || "Tidak diketahui",
          repository: repo,
          branch: link.productionBranch || "main",
          canDeploy,
          createdAt: p.createdAt || null
        };
      });

      return json({ projects: result });
    }

    // HISTORY
    if (path === "/api/history" && method === "GET") {
      const history =
        await env.HISTORY.get(HISTORY_KEY, "json") || [];

      return json({
        history: Array.isArray(history) ? history : []
      });
    }

    // DEPLOYMENT LIST
    if (path === "/api/deployments" && method === "GET") {
      const projectId = url.searchParams.get("projectId");
      const deployments = await getDeployments(env, projectId);

      return json({ deployments });
    }

    // RENAME PROJECT
    if (path === "/api/rename" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);
      const name = String(body.name || "").trim();

      if (!name || name.length > 100) {
        throw new HttpError("Nama proyek tidak valid.", 400);
      }

      try {
        const result = await vercelFetch(
          "/v9/projects/" + encodeURIComponent(project.id),
          env,
          {
            method: "PATCH",
            body: { name }
          }
        );

        await saveHistory(env, {
          action: "Rename",
          title: project.name,
          detail: "Nama proyek diubah menjadi " + name,
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

    // DELETE PROJECT
    if (path === "/api/delete" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);

      if (body.confirmName !== project.name) {
        throw new HttpError(
          "Konfirmasi nama proyek tidak cocok.",
          400
        );
      }

      try {
        await vercelFetch(
          "/v9/projects/" + encodeURIComponent(project.id),
          env,
          { method: "DELETE" }
        );

        await saveHistory(env, {
          action: "Delete",
          title: project.name,
          detail: "Proyek berhasil dihapus dari Vercel.",
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

    // DEPLOY DARI GITHUB
    if (path === "/api/deploy" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);

      const branch = String(body.branch || "").trim();
      const target = body.target === "production"
        ? "production"
        : null;

      if (!branch || branch.length > 200) {
        throw new HttpError("Nama branch tidak valid.", 400);
      }

      const link = project.link || {};

      if (
        link.type !== "github" ||
        !(link.repoId || (link.org && link.repo))
      ) {
        throw new HttpError(
          "Proyek ini belum terhubung ke repository GitHub di Vercel.",
          400
        );
      }

      const gitSource = {
        type: "github",
        ref: branch
      };

      if (link.repoId) {
        gitSource.repoId = link.repoId;
      } else {
        gitSource.org = link.org;
        gitSource.repo = link.repo;
      }

      const payload = {
        name: project.name,
        project: project.id,
        gitSource
      };

      if (target) payload.target = target;

      try {
        const result = await vercelFetch(
          "/v13/deployments?forceNew=1",
          env,
          {
            method: "POST",
            body: payload
          }
        );

        await saveHistory(env, {
          action: "Deploy",
          title: project.name,
          detail: "Branch " + branch + " · " +
            (target || "preview"),
          status: result.readyState || "QUEUED",
          url: result.url
            ? "https://" + result.url
            : ""
        });

        return json({
          success: true,
          deployment: {
            id: result.id,
            url: result.url || "",
            state: result.readyState || "QUEUED",
            inspectorUrl: result.inspectorUrl || ""
          }
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

    // REDEPLOY DEPLOYMENT TERBARU
    if (path === "/api/redeploy" && method === "POST") {
      const body = await readBody(request);
      const project = await getProject(env, body.projectId);

      const deployments = await getDeployments(env, project.id);
      const latest = deployments[0];

      if (!latest || !latest.id) {
        throw new HttpError(
          "Belum ada deployment yang bisa di-redeploy.",
          404
        );
      }

      try {
        const result = await vercelFetch(
          "/v13/deployments?forceNew=1",
          env,
          {
            method: "POST",
            body: {
              name: project.name,
              project: project.id,
              deploymentId: latest.id,
              withLatestCommit: true
            }
          }
        );

        await saveHistory(env, {
          action: "Redeploy",
          title: project.name,
          detail: "Menjalankan ulang deployment terbaru.",
          status: result.readyState || "QUEUED",
          url: result.url
            ? "https://" + result.url
            : ""
        });

        return json({
          success: true,
          deployment: {
            id: result.id,
            url: result.url || "",
            state: result.readyState || "QUEUED",
            inspectorUrl: result.inspectorUrl || ""
          }
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
    console.error(error);

    return json(
      { error: error.message || "Server error." },
      error.status || 500
    );
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, env);
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("Asset binding ASSETS belum dipasang.", {
        status: 500
      });
    } catch (error) {
      return json({ error: error.message || "Internal error." }, 500);
    }
  }
};
