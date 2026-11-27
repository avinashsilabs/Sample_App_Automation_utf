const $ = (id) => document.getElementById(id);

const params = new URLSearchParams(window.location.search);
const appId = params.get("app_id") || "";
const bleRoot = params.get("ble_root") || "";
const sdkRoot = params.get("sdk_root") || "";
const target = params.get("target") || "soc";
const board = params.get("board") || "";
const toolchain = params.get("toolchain") || "gcc";

let headers = [];
let currentPath = null;
const dirty = new Map();
const originals = new Map();

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function query() {
  const q = new URLSearchParams({ app_id: appId });
  if (bleRoot) q.set("ble_root", bleRoot);
  if (target) q.set("target", target);
  if (toolchain) q.set("toolchain", toolchain);
  return q.toString();
}

function bodyExtra() {
  const b = { app_id: appId };
  if (bleRoot) b.ble_root = bleRoot;
  return b;
}

function setDirtyBadge(show) {
  $("dirty-badge").classList.toggle("hidden", !show);
}

function renderList() {
  const ul = $("header-list");
  ul.innerHTML = "";
  let lastCategory = null;
  headers.forEach((h) => {
    if (h.category !== lastCategory) {
      lastCategory = h.category;
      const heading = document.createElement("li");
      heading.className = "header-group";
      heading.textContent = h.category === "config" ? "Project config (output/config)" : "Application source";
      ul.appendChild(heading);
    }
    const li = document.createElement("li");
    li.textContent = h.path;
    li.title = h.path;
    if (h.path === currentPath) li.classList.add("active");
    if (dirty.has(h.path)) li.classList.add("dirty");
    li.addEventListener("click", () => selectHeader(h.path));
    ul.appendChild(li);
  });
}

async function selectHeader(path) {
  if (currentPath && dirty.has(currentPath)) {
    dirty.set(currentPath, $("editor").value);
  }
  currentPath = path;
  $("current-file").textContent = path;
  $("editor").disabled = false;

  if (dirty.has(path)) {
    $("editor").value = dirty.get(path);
    setDirtyBadge(true);
    renderList();
    return;
  }

  const data = await api(`/api/app/header?${query()}&path=${encodeURIComponent(path)}`);
  originals.set(path, data.content);
  $("editor").value = data.content;
  setDirtyBadge(false);
  renderList();
}

$("editor").addEventListener("input", () => {
  if (!currentPath) return;
  const val = $("editor").value;
  if (val !== originals.get(currentPath)) {
    dirty.set(currentPath, val);
    setDirtyBadge(true);
  } else {
    dirty.delete(currentPath);
    setDirtyBadge(dirty.size > 0);
  }
  renderList();
});

async function saveAll() {
  if (currentPath && $("editor").value !== originals.get(currentPath)) {
    dirty.set(currentPath, $("editor").value);
  }
  for (const [path, content] of dirty.entries()) {
    await api("/api/app/header", {
      method: "PUT",
      body: JSON.stringify({ ...bodyExtra(), path, content }),
    });
    originals.set(path, content);
  }
  dirty.clear();
  setDirtyBadge(false);
  renderList();
}

async function saveAndContinue() {
  await saveAll();
  if (window.opener && !window.opener.closed) {
    window.opener.postMessage({
      type: "wc-config-saved",
      buildFlash: true,
      app_id: appId,
      sdk_root: sdkRoot,
      ble_root: bleRoot,
      target,
      board,
      toolchain,
    }, window.location.origin);
    window.close();
  } else {
    const q = new URLSearchParams({
      app_id: appId,
      sdk_root: sdkRoot,
      ble_root: bleRoot,
      target,
      board,
      toolchain,
      autobuild: "1",
    });
    window.location.href = `/?${q}`;
  }
}

async function init() {
  if (!appId) {
    $("config-subtitle").textContent = "No application selected";
    return;
  }
  const data = await api(`/api/app/headers?${query()}`);
  headers = data.headers || [];
  $("config-subtitle").textContent = `${appId} [${target}/${toolchain}] — ${data.count} header(s)`;
  if (!headers.length) {
    $("header-list").innerHTML = '<li class="muted">No header files found. Run Build once to generate project config headers.</li>';
    return;
  }
  renderList();
  await selectHeader(headers[0].path);
}

$("btn-save").addEventListener("click", () => saveAll().catch((e) => alert(e.message)));
$("btn-save-continue").addEventListener("click", () => saveAndContinue().catch((e) => alert(e.message)));

init().catch((e) => alert(e.message));
