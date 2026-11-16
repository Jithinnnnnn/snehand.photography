// Backend for admin.html (runs on Netlify, never visible to site visitors).
const crypto = require("crypto");

// Credentials are stored only as hashes (not readable in plain text).
const _k1 = "d0184ac0bb805931ebcbae88e12dc44b4c15309444cf141ba02d29b041f1679a";
const _k2 = "2465af08853297c60192e0a7b36d8ff197c50dbf27f829f7e8f9f7a44c5fff64";

const sha = (s) => crypto.createHash("sha256").update(String(s || "")).digest("hex");
const same = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

const FOLDER = "public";
const reply = (code, obj) => ({
  statusCode: code,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify(obj),
});

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return reply(405, { error: "POST only" });

  let b;
  try { b = JSON.parse(event.body || "{}"); } catch { return reply(400, { error: "Bad request" }); }

  if (!same(sha(b.u), _k1) || !same(sha(b.p), _k2)) {
    await new Promise((r) => setTimeout(r, 800)); // slow down guessing
    return reply(401, { error: "Wrong username or password" });
  }

  if (b.action === "login") return reply(200, { ok: true });

  const { GH_TOKEN, GH_REPO } = process.env; // GH_REPO = "owner/repo"
  const branch = process.env.GH_BRANCH || "main";
  if (!GH_TOKEN || !GH_REPO) return reply(500, { error: "GH_TOKEN / GH_REPO not set in Netlify" });

  const api = (path, opt = {}) =>
    fetch(`https://api.github.com/repos/${GH_REPO}/contents/${path}`, {
      ...opt,
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${GH_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "snehand-admin",
        ...(opt.headers || {}),
      },
    });

  const ghErr = async (r) => {
    try { const j = await r.json(); return r.status + " " + (j.message || ""); }
    catch { return String(r.status); }
  };

  // Use the file name exactly as it is on GitHub; only block anything that could escape the folder.
  const clean = (n) => {
    n = String(n || "");
    if (!n || /[\/\\]/.test(n) || n.startsWith(".") || n.includes("..")) return null;
    return n;
  };
  const enc = encodeURIComponent;

  try {
    if (b.action === "login") return reply(200, { ok: true });

    if (b.action === "list") {
      const r = await api(`${FOLDER}?ref=${branch}&t=${Date.now()}`);
      if (!r.ok) return reply(500, { error: "Could not read folder: " + (await ghErr(r)) });
      const all = await r.json();
      if (!Array.isArray(all)) return reply(500, { error: "'public' on GitHub is not a folder" });
      const files = all
        .filter((f) => f.type === "file" && /\.jpe?g$/i.test(f.name))
        .map((f) => {
          const d = f.download_url || "";
          return {
            name: f.name,
            sha: f.sha,
            // image served by GitHub itself; ?v=sha makes it refresh after a replace
            url: d ? d + (d.includes("?") ? "&" : "?") + "v=" + f.sha : `/${FOLDER}/${f.name}`,
            local: `/${FOLDER}/${f.name}`,
          };
        });
      return reply(200, { files, seen: all.map((f) => f.name), repo: GH_REPO, branch });
    }

    if (b.action === "upload") {
      const name = clean(b.name);
      if (!name || !/\.jpe?g$/i.test(name)) return reply(400, { error: "JPG images only" });
      const path = `${FOLDER}/${enc(name)}`;
      const ex = await api(`${path}?ref=${branch}`);          // must already exist (replace only)
      if (!ex.ok) return reply(400, { error: "Replace only: " + name + " does not exist in /public" });
      const sha1 = (await ex.json()).sha;
      const r = await api(path, {
        method: "PUT",
        body: JSON.stringify({ message: `Admin: upload ${name}`, content: b.content, branch, sha: sha1 }),
      });
      return r.ok ? reply(200, { ok: true }) : reply(500, { error: "Upload failed: " + (await ghErr(r)) });
    }

    if (b.action === "delete") {
      const name = clean(b.name);
      if (!name) return reply(400, { error: "Bad file name" });
      const path = `${FOLDER}/${enc(name)}`;
      // always use the file's CURRENT id from GitHub, not the one the page loaded earlier
      const ex = await api(`${path}?ref=${branch}`);
      if (ex.status === 404) return reply(200, { ok: true, note: "already deleted" });
      if (!ex.ok) return reply(500, { error: "Delete failed (lookup): " + (await ghErr(ex)) });
      const cur = (await ex.json()).sha;
      const r = await api(path, {
        method: "DELETE",
        body: JSON.stringify({ message: `Admin: delete ${name}`, sha: cur, branch }),
      });
      return r.ok ? reply(200, { ok: true }) : reply(500, { error: "Delete failed: " + (await ghErr(r)) });
    }

    return reply(400, { error: "Unknown action" });
  } catch (e) {
    console.error(e);
    return reply(500, { error: "Server error: " + e.message });
  }
};
