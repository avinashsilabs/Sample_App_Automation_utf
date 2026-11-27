const $ = (id) => document.getElementById(id);

const FLASHABLE = [".rps", ".hex", ".s37", ".bin"];
const API_TIMEOUT_MS = 15000;
const API_POLL_TIMEOUT_MS = 120000;
const INTEGRATION_POLL_TIMEOUT_MS = 60000;
const BLE_STEP_TIMEOUT_MS = 240000;
const UTF_POLL_MAX_CONSECUTIVE_ERRORS = 30;

let currentJobId = null;
let currentArtifacts = [];
let pollTimer = null;
let serialTimer = null;
let serialLineCount = 0;
let buildFlashMode = false;
const DEFAULT_BOARDS = {
  soc: [
    { id: "brd4338a", label: "BRD4338A (SiWx917 SoC)" },
    { id: "brd4343a", label: "BRD4343A (SiWx917 SoC)" },
    { id: "brd4346a", label: "BRD4346A (SiWx917 SoC)" },
    { id: "brd2605b", label: "BRD2605B (SiWx917 SoC)" },
  ],
  ncp: [
    { id: "brd4186c", label: "BRD4186C (EFR32 NCP Host)" },
    { id: "brd4180a", label: "BRD4180A (EFR32 NCP Host)" },
  ],
};

let boards = structuredClone(DEFAULT_BOARDS);
/** @type {Record<string, object|null>} */
let appTestProfiles = {};

async function api(path, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? API_TIMEOUT_MS;
  const { timeoutMs: _drop, ...fetchOpts } = opts;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      ...fetchOpts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText || `HTTP ${res.status}`);
    return data;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`Request timed out (${timeoutMs / 1000}s) — is the server running?`);
    }
    if (err.message === "Failed to fetch") {
      throw new Error("Cannot reach server — run: python app.py");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function log(line) {
  const el = $("log-output");
  el.textContent += line + "\n";
  el.scrollTop = el.scrollHeight;
}

function clearLog() {
  $("log-output").textContent = "";
}

function setStatus(text, cls = "") {
  const el = $("build-status");
  el.textContent = text;
  el.className = "badge " + cls;
}

function showErrorDialog(title, message) {
  const dlg = $("error-dialog");
  if (!dlg) {
    alert(`${title}\n\n${message}`);
    return;
  }
  $("error-dialog-title").textContent = title;
  $("error-dialog-body").textContent = message;
  dlg.showModal();
}

function buildPayload() {
  return {
    app_id: $("app-select").value,
    target: $("target-select").value,
    board: selectedBoard(),
    toolchain: $("toolchain-select").value,
    sdk_root: selectedSdkRoot(),
    ble_root: $("ble-root").value.trim() || undefined,
    adapter_serial: selectedAdapterSerial(),
    artifact_path: undefined,
  };
}

function validateBuildPayload(payload) {
  if (!payload.board) return "Select a board first";
  if (!payload.app_id || payload.app_id === "Failed to load apps") return "Select a valid BLE example first";
  if (!payload.sdk_root) return "Set SDK root path";
  return null;
}

function openConfig() {
  const payload = buildPayload();
  const err = validateBuildPayload(payload);
  if (err) {
    showErrorDialog("Config", err);
    return;
  }
  const q = new URLSearchParams({
    app_id: payload.app_id,
    sdk_root: payload.sdk_root,
    target: payload.target,
    board: payload.board,
    toolchain: payload.toolchain,
  });
  if (payload.ble_root) q.set("ble_root", payload.ble_root);
  window.open(`/config?${q}`, "wc-config", "width=1100,height=800");
}

function showConsoleView(name) {
  const views = { build: "main-view", serial: "serial-view", utf: "utf-view" };
  Object.entries(views).forEach(([key, id]) => {
    $(id)?.classList.toggle("hidden", key !== name);
  });
  document.querySelectorAll(".console-nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.console === name);
  });
  if (name === "serial") {
    loadSerialPorts().catch(() => {});
  }
}

function showBuildView() {
  showConsoleView("build");
}

function showSerialView(suggestedPort) {
  showConsoleView("serial");
  const load = suggestedPort
    ? loadSerialPorts(suggestedPort).then(() => startSerialMonitor())
    : loadSerialPorts();
  load.catch(() => {});
}

function showUtfView() {
  showConsoleView("utf");
}

async function loadSerialPorts(suggested) {
  try {
    const data = await api("/api/serial/ports");
    const selects = ["serial-port", "serial-port-view"].map((id) => $(id)).filter(Boolean);
    selects.forEach((sel) => {
      const isSidebar = sel.id === "serial-port";
      sel.innerHTML = "";
      if (isSidebar) {
        const auto = document.createElement("option");
        auto.value = "";
        auto.textContent = "Auto-detect VCOM";
        sel.appendChild(auto);
      }
      (data.ports || []).forEach((p) => {
        const opt = document.createElement("option");
        opt.value = p.device;
        opt.textContent = `${p.device} — ${p.description}`;
        sel.appendChild(opt);
      });
    });
    const pick = suggested || data.suggested;
    selects.forEach((sel) => {
      if (pick && [...sel.options].some((o) => o.value === pick)) {
        sel.value = pick;
      } else if (!sel.value && sel.options.length) {
        sel.selectedIndex = Math.min(1, sel.options.length - 1);
      }
    });
  } catch (e) {
    log("Serial ports: " + e.message);
  }
}

function selectedSerialPort() {
  return $("serial-port")?.value?.trim() || $("serial-port-view")?.value?.trim() || undefined;
}

async function startSerialMonitor() {
  if (serialTimer) clearInterval(serialTimer);
  serialLineCount = 0;
  const port = $("serial-port-view")?.value || $("serial-port")?.value;
  const baud = parseInt($("serial-baud")?.value || "115200", 10);
  if (!port) {
    $("serial-status").textContent = "No port — select or auto-detect";
    $("serial-status").className = "badge badge-warn";
    return;
  }
  try {
    await api("/api/serial/stop", { method: "POST", body: "{}" });
    await api("/api/serial/start", {
      method: "POST",
      body: JSON.stringify({ port, baud }),
    });
    $("serial-output").textContent = `--- ${port} @ ${baud} ---\n`;
    $("serial-status").textContent = `${port} @ ${baud}`;
    $("serial-status").className = "badge badge-ok";
    serialTimer = setInterval(pollSerial, 500);
  } catch (e) {
    $("serial-status").textContent = "Serial failed";
    $("serial-status").className = "badge badge-err";
    showErrorDialog("Serial Console", e.message);
  }
}

async function pollSerial() {
  try {
    const data = await api(`/api/serial/lines?since=${serialLineCount}`);
    if (data.lines?.length) {
      const el = $("serial-output");
      el.textContent += data.lines.join("\n") + "\n";
      el.scrollTop = el.scrollHeight;
      serialLineCount = data.total;
    }
  } catch (_) { /* ignore transient poll errors */ }
}

async function stopSerialMonitor() {
  if (serialTimer) {
    clearInterval(serialTimer);
    serialTimer = null;
  }
  try {
    await api("/api/serial/stop", { method: "POST", body: "{}" });
  } catch (_) { /* ignore */ }
}

function selectedSdkRoot() {
  const cached = $("sdk-select").value;
  const local = $("sdk-local-path").value.trim();
  return local || cached;
}

function setWorkflowButtonsDisabled(disabled) {
  $("btn-build-flash-test") && ($("btn-build-flash-test").disabled = disabled);
  $("btn-build") && ($("btn-build").disabled = disabled);
  $("btn-flash") && ($("btn-flash").disabled = disabled);
  $("btn-build-flash") && ($("btn-build-flash").disabled = disabled);
  $("btn-launch-utf") && ($("btn-launch-utf").disabled = disabled);
  $("btn-start-connection") && ($("btn-start-connection").disabled = disabled);
}

function setButtonsDisabled(disabled) {
  setWorkflowButtonsDisabled(disabled);
}

async function applyPrebuildConfigurations() {
  const button = $("btn-prebuild-configurations");
  if (button) button.disabled = true;
  try {
    const result = await api("/api/prebuild-configurations", {
      method: "POST",
      body: JSON.stringify({ sdk_root: selectedSdkRoot() }),
    });
    log(`Prebuild configurations were made in ${result.application_count ?? result.changed_count} files`);
  } catch (e) {
    showErrorDialog("Prebuild Configurations", e.message);
  } finally {
    if (button) button.disabled = false;
  }
}

async function loadTools() {
  const el = $("tool-status");
  try {
    const t = await api("/api/tools");
    if (t.ready) {
      el.textContent = t.llvm_ready ? "Tools OK (GCC + LLVM)" : "Tools OK (GCC)";
      el.className = "badge badge-ok";
    } else {
      el.textContent = "Tools missing — install via SLT";
      el.className = "badge badge-warn";
    }
  } catch (e) {
    el.textContent = "Server offline";
    el.className = "badge badge-err";
    log("Tools check failed: " + e.message);
  }
}

async function loadApps() {
  const bleRoot = $("ble-root").value.trim();
  const sdkRoot = selectedSdkRoot();
  const params = new URLSearchParams();
  if (bleRoot) params.set("ble_root", bleRoot);
  else if (sdkRoot) params.set("sdk_root", sdkRoot);
  const q = params.toString() ? `?${params}` : "";

  const sel = $("app-select");
  try {
    const data = await api("/api/apps" + q);
    if (!bleRoot && data.ble_root) {
      $("ble-root").placeholder = data.ble_root;
    }
    sel.innerHTML = "";
    if (!data.apps?.length) {
      const opt = document.createElement("option");
      opt.textContent = data.exists === false
        ? "No BLE examples found — check SDK root"
        : "No BLE apps found";
      sel.appendChild(opt);
      log(data.error || `Apps: 0 found (root: ${data.ble_root || "unset"})`);
      return;
    }
    data.apps.forEach((app) => {
      const opt = document.createElement("option");
      opt.value = app.id;
      opt.dataset.testFunction = app.test_function || "";
      opt.dataset.exampleKind = app.example_kind || "ble";
      appTestProfiles[app.id] = app.test_profile || null;
      const tags = [];
      if (app.soc_slcp) tags.push("SoC");
      if (app.ncp_slcp) tags.push("NCP");
      opt.textContent = `${app.label} (${tags.join(", ")})`;
      sel.appendChild(opt);
    });
    updateAppTestHint();
    log(`Loaded ${data.count} examples from ${data.ble_root}`);
  } catch (e) {
    sel.innerHTML = "";
    const opt = document.createElement("option");
    opt.textContent = "Failed to load apps";
    sel.appendChild(opt);
    log("Apps load failed: " + e.message);
  }
}

async function loadBoards() {
  try {
    const data = await api("/api/boards");
    if (data?.soc?.length || data?.ncp?.length) {
      boards = data;
    }
  } catch (e) {
    log("Boards load failed (using defaults): " + e.message);
    boards = structuredClone(DEFAULT_BOARDS);
  }
  updateBoards();
}

function updateBoards() {
  const target = $("target-select")?.value || "soc";
  const sel = $("board-select");
  if (!sel) return;

  const list = boards[target]?.length ? boards[target] : (DEFAULT_BOARDS[target] || []);
  const prev = sel.value;
  sel.innerHTML = "";
  list.forEach((b) => {
    const opt = document.createElement("option");
    opt.value = b.id;
    opt.textContent = b.label;
    sel.appendChild(opt);
  });
  if (prev && [...sel.options].some((o) => o.value === prev)) {
    sel.value = prev;
  }
}

function selectedBoard() {
  const sel = $("board-select");
  const val = sel?.value;
  if (val) return val;
  const target = $("target-select")?.value || "soc";
  return DEFAULT_BOARDS[target]?.[0]?.id || "brd4338a";
}

async function loadSdks() {
  try {
    const data = await api("/api/sdks");
    const sel = $("sdk-select");
    sel.innerHTML = "";
    data.sdks.forEach((sdk) => {
      const opt = document.createElement("option");
      opt.value = sdk.sdk_root;
      opt.textContent = `${sdk.name} ${sdk.valid ? "✓" : "(invalid)"}`;
      sel.appendChild(opt);
    });
    if (data.default && !$("sdk-local-path").value) {
      $("sdk-local-path").value = data.default;
    }
  } catch (e) {
    log("SDK list failed: " + e.message);
  }
}

async function validateSdk() {
  const path = $("sdk-local-path").value.trim();
  const el = $("sdk-local-status");
  if (!path) {
    el.textContent = "Enter the SDK root path for this machine";
    el.className = "hint err";
    return;
  }
  el.textContent = "Validating layout and trusting SDK + WiSeConnect…";
  el.className = "hint";
  log(`Validate SDK: ${path}`);
  try {
    const info = await api("/api/sdk/validate", {
      method: "POST",
      body: JSON.stringify({ sdk_root: path }),
    });
    (info.logs || []).forEach((line) => log(line));
    $("sdk-local-path").value = info.sdk_root;
    if (info.ble_root) {
      $("ble-root").value = info.ble_root;
    }
    const appsHint = info.ble_root
      ? `examples: ${info.ble_root}`
      : "no BLE examples folder found";
    el.textContent = info.trusted
      ? `Valid & trusted — ${info.sdk_root} (${appsHint})`
      : `Valid — ${info.sdk_root} (${appsHint})`;
    el.className = "hint ok";
    log(`SDK trusted. Select a BLE example and click Build.`);
    await loadSdks();
    await loadApps();
  } catch (e) {
    el.textContent = e.message;
    el.className = "hint err";
    log("Validate failed: " + e.message);
  }
}

async function downloadSdk() {
  const el = $("sdk-download-status");
  el.textContent = "Downloading…";
  el.className = "hint";
  try {
    const data = await api("/api/sdk/download", {
      method: "POST",
      body: JSON.stringify({
        gecko_url: $("gecko-url").value.trim(),
        wiseconnect_url: $("wiseconnect-url").value.trim(),
        name: $("sdk-cache-name").value.trim(),
      }),
    });
    pollSdkDownload(data.job_id, el);
  } catch (e) {
    el.textContent = e.message;
    el.className = "hint err";
  }
}

function pollSdkDownload(jobId, el) {
  const timer = setInterval(async () => {
    try {
      const job = await api(`/api/sdk/download/${jobId}`);
      el.textContent = job.logs?.slice(-1)[0] || job.status;
      if (job.status === "success") {
        clearInterval(timer);
        el.textContent = `Ready: ${job.sdk.sdk_root}`;
        el.className = "hint ok";
        $("sdk-local-path").value = job.sdk.sdk_root;
        await loadSdks();
        await loadApps();
      } else if (job.status === "failed") {
        clearInterval(timer);
        el.textContent = job.error || "Download failed";
        el.className = "hint err";
      }
    } catch (e) {
      clearInterval(timer);
      el.textContent = e.message;
      el.className = "hint err";
    }
  }, 1500);
}

async function loadAdapters() {
  try {
    const data = await api("/api/adapters");
    const ul = $("adapter-list");
    const sel = $("adapter-select");
    if (!ul && !sel) return;
    if (ul) ul.innerHTML = "";
    if (sel) sel.innerHTML = '<option value="">Default adapter</option>';

    if (data.adapters?.length) {
      data.adapters.forEach((a) => {
        if (ul) {
          const li = document.createElement("li");
          li.textContent = `#${a.index}: ${a.info}`;
          ul.appendChild(li);
        }

        if (sel) {
          const opt = document.createElement("option");
          opt.value = a.serial || "";
          opt.textContent = a.serial ? `#${a.index} (${a.serial})` : `#${a.index}: ${a.info}`;
          sel.appendChild(opt);
        }
      });
    } else if (ul) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = `No debug adapters (deviceCount=${data.device_count ?? 0})`;
      ul.appendChild(li);
    }
  } catch (e) {
    log("Adapters: " + e.message);
  }
}

function selectedAdapterSerial() {
  return $("adapter-select").value || undefined;
}

async function getDeviceInfo() {
  const serial = selectedAdapterSerial();
  const q = serial ? `?serial=${encodeURIComponent(serial)}` : "";
  setStatus("Reading device…", "badge-run");
  log("Running commander device info …");
  try {
    const result = await api("/api/device/info" + q);
    $("device-info").textContent = result.output || "(no output)";
    $("device-info").classList.remove("muted");
    log(result.output || "");
    setStatus("Device info OK", "badge-ok");
  } catch (e) {
    $("device-info").textContent = e.message;
    log("Device info error: " + e.message);
    setStatus("No device", "badge-err");
  }
}

async function recoverDevice() {
  setStatus("Recovering…", "badge-run");
  log("Running commander device recover …");
  try {
    const result = await api("/api/device/recover", {
      method: "POST",
      body: JSON.stringify({ adapter_serial: selectedAdapterSerial() }),
    });
    log(result.output || "Recover complete");
    setStatus("Recovered", "badge-ok");
    await getDeviceInfo();
  } catch (e) {
    log("Recover error: " + e.message);
    setStatus("Recover failed", "badge-err");
  }
}

function populateFlashArtifacts(artifacts) {
  currentArtifacts = artifacts || [];
  const sel = $("flash-artifact");
  if (!sel) return;
  sel.innerHTML = "";
  const flashable = currentArtifacts.filter((a) => FLASHABLE.includes(a.ext));

  if (!flashable.length) {
    sel.disabled = true;
    const opt = document.createElement("option");
    opt.textContent = "No flashable artifacts";
    sel.appendChild(opt);
    return;
  }

  sel.disabled = false;
  flashable.forEach((a) => {
    const opt = document.createElement("option");
    opt.value = a.path;
    opt.textContent = `${a.ext}  ${a.name}  (${(a.size / 1024).toFixed(1)} KB)`;
    sel.appendChild(opt);
  });
}

function showArtifacts(artifacts) {
  const el = $("artifacts");
  if (!artifacts?.length) {
    el.innerHTML = '<p class="muted">No artifacts produced</p>';
    populateFlashArtifacts([]);
    return;
  }
  el.innerHTML = artifacts.map((a) => {
    const flashable = FLASHABLE.includes(a.ext);
    return `<div class="artifact${flashable ? " flashable" : ""}"><strong>${a.ext}</strong> ${a.name}<br><span class="muted">${(a.size / 1024).toFixed(1)} KB${flashable ? " · flashable" : ""}</span></div>`;
  }).join("");
  populateFlashArtifacts(artifacts);
}

async function startBuild(flashAfter = false) {
  buildFlashMode = flashAfter;
  showConsoleView("build");
  clearLog();
  setStatus(flashAfter ? "Build & Flash…" : "Building…", "badge-run");
  setButtonsDisabled(true);

  const payload = buildPayload();
  const err = validateBuildPayload(payload);
  if (err) {
    log(err);
    setButtonsDisabled(false);
    setStatus("Invalid config", "badge-err");
    showErrorDialog("Build", err);
    return;
  }

  log(`${flashAfter ? "Build & Flash" : "Build"}: ${payload.app_id} [${payload.target}] ${payload.toolchain}`);
  try {
    const endpoint = flashAfter ? "/api/build-flash" : "/api/build";
    const data = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
    currentJobId = data.job_id;
    pollBuild(data.job_id);
  } catch (e) {
    log("Build start failed: " + e.message);
    setStatus("Build failed", "badge-err");
    setButtonsDisabled(false);
    showErrorDialog("Build Failed", e.message);
  }
}

function startBuildFlash() {
  startBuild(true);
}

function pollBuild(jobId) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const job = await api(`/api/build/${jobId}`);
      $("log-output").textContent = job.logs.join("\n") + "\n";
      $("log-output").scrollTop = $("log-output").scrollHeight;

      if (job.status === "running") {
        if (job.phase === "flash") {
          setStatus("Flashing…", "badge-run");
        } else {
          setStatus(buildFlashMode ? "Building…" : "Building…", "badge-run");
        }
      } else if (job.status === "success") {
        clearInterval(pollTimer);
        showArtifacts(job.artifacts);
        setButtonsDisabled(false);
        $("btn-flash").disabled = false;

        if (buildFlashMode) {
          setStatus("Flashed — serial listening", "badge-ok");
          log("=== Build & Flash complete — opening serial console ===");
          const port = job.serial_port || selectedSerialPort();
          setTimeout(() => showSerialView(port), 400);
        } else {
          setStatus("Success", "badge-ok");
        }
      } else if (job.status === "failed") {
        clearInterval(pollTimer);
        setStatus("Failed", "badge-err");
        setButtonsDisabled(false);
        const msg = job.error || "unknown";
        log("ERROR: " + msg);
        if (buildFlashMode && job.phase === "flash") {
          showErrorDialog("Flash Failed", msg);
        } else {
          showErrorDialog("Build Failed", msg);
        }
      }
    } catch (e) {
      clearInterval(pollTimer);
      log("Poll error: " + e.message);
      setButtonsDisabled(false);
      showErrorDialog("Error", e.message);
    }
  }, 1200);
}

async function flash() {
  if (!currentJobId) return;
  const sel = $("flash-artifact");
  const artifactPath = sel?.value;
  if (sel && !artifactPath) {
    log("Select a flash image (.rps, .hex, .bin) first");
    return;
  }
  setStatus("Flashing…", "badge-run");
  log(`Flashing ${artifactPath} …`);
  try {
    const result = await api("/api/flash", {
      method: "POST",
      body: JSON.stringify({
        job_id: currentJobId,
        artifact_path: artifactPath,
        adapter_serial: selectedAdapterSerial(),
        auto_recover: true,
      }),
    });
    log("Flashed: " + result.flashed);
    log(result.output || "");
    setStatus("Flashed", "badge-ok");
    if (result.serial_port) {
      setTimeout(() => showSerialView(result.serial_port), 400);
    }
  } catch (e) {
    log("Flash error: " + e.message);
    setStatus("Flash failed", "badge-err");
    showErrorDialog("Flash Failed", e.message);
  }
}

function applyUrlParams() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("sdk_root")) $("sdk-local-path").value = params.get("sdk_root");
  if (params.get("ble_root")) $("ble-root").value = params.get("ble_root");
  if (params.get("target")) $("target-select").value = params.get("target");
  if (params.get("board")) $("board-select").value = params.get("board");
  if (params.get("toolchain")) $("toolchain-select").value = params.get("toolchain");
  updateBoards();
  if (params.get("board")) $("board-select").value = params.get("board");
  return params.get("autobuild") === "1" || params.get("autobuild") === "true";
}

function handleConfigMessage(event) {
  if (event.origin !== window.location.origin) return;
  if (event.data?.type !== "wc-config-saved") return;
  const d = event.data;
  if (d.sdk_root) $("sdk-local-path").value = d.sdk_root;
  if (d.ble_root) $("ble-root").value = d.ble_root;
  if (d.target) $("target-select").value = d.target;
  if (d.board) $("board-select").value = d.board;
  if (d.toolchain) $("toolchain-select").value = d.toolchain;
  updateBoards();
  if (d.board) $("board-select").value = d.board;
  loadApps().then(() => {
    if (d.app_id) $("app-select").value = d.app_id;
    if (d.buildFlash) startBuildFlash();
  });
}

function bleRootPath() {
  const v = $("ble-root")?.value?.trim();
  if (v) return v;
  const ph = $("ble-root")?.placeholder;
  if (ph && !ph.startsWith("Derived")) return ph;
  return undefined;
}

let currentUtfJobId = null;
let utfPollTimer = null;
let currentIntegrationJobId = null;
let integrationPollTimer = null;

const UTF_WORKSPACE_KEY = "wc_utf_workspace_root";
const UTF_TARGET_KEY = "wc_utf_target";
const UTF_HARNESS_KEY = "wc_utf_harness";
const UTF_PASSKEY_KEY = "wc_use_passkey";
const UTF_DUT_ADDRESS_KEY = "wc_ble_dut_address";

function saveUtfSettings() {
  const root = $("utf-workspace-root")?.value?.trim();
  const target = $("utf-target")?.value?.trim();
  const harness = $("utf-harness")?.value?.trim();
  const passkey = $("use-passkey")?.checked;
  const dutAddr = $("ble-dut-address")?.value?.trim();
  if (root) localStorage.setItem(UTF_WORKSPACE_KEY, root);
  if (target) localStorage.setItem(UTF_TARGET_KEY, target);
  if (harness) localStorage.setItem(UTF_HARNESS_KEY, harness);
  localStorage.setItem(UTF_PASSKEY_KEY, passkey ? "1" : "0");
  if (dutAddr) localStorage.setItem(UTF_DUT_ADDRESS_KEY, dutAddr);
  else localStorage.removeItem(UTF_DUT_ADDRESS_KEY);
  updateUtfHint();
}

function updateUtfHint() {
  const el = $("utf-hint");
  if (!el) return;
  const root = $("utf-workspace-root")?.value?.trim();
  const target = $("utf-target")?.value?.trim();
  const harness = $("utf-harness")?.value?.trim();
  const app = $("app-select")?.selectedOptions?.[0];
  const testFn = app?.dataset?.testFunction;
  if (root && target && harness) {
    let line = `.\\launch_utf_tests.bat --target=${target} --harness=${harness}`;
    if (testFn) line += `  →  ${testFn}`;
    el.textContent = line;
    el.className = "hint ok";
  } else {
    el.textContent = "Set utf_wifi root, Raspberry Pi IP, and harness.";
    el.className = "hint";
  }
}

async function loadUtfSettings() {
  let defaults = { workspace_root: "", executor_dir: "", target: "", harness: "" };
  try {
    defaults = await api("/api/utf/defaults");
  } catch (_) { /* use empty defaults */ }
  $("utf-workspace-root").value =
    localStorage.getItem(UTF_WORKSPACE_KEY) || defaults.workspace_root || "";
  $("utf-target").value =
    localStorage.getItem(UTF_TARGET_KEY) || defaults.target || "";
  $("utf-harness").value =
    localStorage.getItem(UTF_HARNESS_KEY) || defaults.harness || "";
  $("use-passkey").checked = localStorage.getItem(UTF_PASSKEY_KEY) === "1";
  const dutStored = localStorage.getItem(UTF_DUT_ADDRESS_KEY);
  if (dutStored && $("ble-dut-address")) $("ble-dut-address").value = dutStored;
  updateUtfHint();
}

function setUtfStatus(text, cls = "") {
  const el = $("utf-status");
  if (!el) return;
  el.textContent = text;
  el.className = "badge " + cls;
}

function appendUtfLog(line) {
  const el = $("utf-log-output");
  if (!el) return;
  el.textContent += line + "\n";
  el.scrollTop = el.scrollHeight;
}

function clearUtfLog() {
  const el = $("utf-log-output");
  if (el) el.textContent = "";
}

async function pollUtfJobStream(jobId, onStatus) {
  let since = 0;
  while (true) {
    try {
      const job = await api(`/api/utf/${jobId}?since=${since}`, { timeoutMs: API_POLL_TIMEOUT_MS });
      if (job.lines?.length) {
        job.lines.forEach((line) => appendUtfLog(line));
        since += job.lines.length;
      }
      if (onStatus) onStatus(job);
      if (job.status && job.status !== "running" && job.status !== "queued") {
        return job;
      }
    } catch (e) {
      appendUtfLog(`[utf poll error] ${e.message}`);
      return null;
    }
    await new Promise((r) => setTimeout(r, 800));
  }
}

function setUtfButtonsRunning(running) {
  $("btn-utf-stop-console") && ($("btn-utf-stop-console").disabled = !running);
}

function utfPayloadExtras() {
  saveUtfSettings();
  const utf_wifi_root = $("utf-workspace-root")?.value?.trim();
  const pi_ip = $("utf-target")?.value?.trim();
  const harness = $("utf-harness")?.value?.trim();
  const dut_address = bleDutAddress() || undefined;
  return { utf_wifi_root, pi_ip, harness, dut_address };
}

function validateUtfSettings({ utf_wifi_root, pi_ip, harness }, title = "UTF") {
  if (!utf_wifi_root || !pi_ip || !harness) {
    showErrorDialog(title, "utf_wifi root, Raspberry Pi IP, and harness are required");
    return false;
  }
  return true;
}

async function launchUtf() {
  const payload = buildPayload();
  const err = validateBuildPayload(payload);
  if (err) {
    showErrorDialog("Launch UTF", err);
    return;
  }
  const { utf_wifi_root, pi_ip, harness } = utfPayloadExtras();
  if (!validateUtfSettings({ utf_wifi_root, pi_ip, harness }, "Launch UTF")) return;

  clearUtfLog();
  showUtfView();
  setUtfStatus("Launching UTF on Raspberry Pi…", "badge-run");
  setUtfButtonsRunning(true);
  appendUtfLog("=== Launch UTF — docker deploy + app-specific pytest on Raspberry Pi ===");
  appendUtfLog(`Pi: ${pi_ip}  harness: ${harness}  app: ${payload.app_id}`);
  appendUtfLog("(You can click Start Connection while docker deploy runs — it waits for Pi /health)");

  try {
    const data = await api("/api/launch-utf", {
      method: "POST",
      body: JSON.stringify({
        ...payload,
        utf_wifi_root,
        pi_ip,
        harness,
      }),
    });
    currentUtfJobId = data.job_id;
    appendUtfLog(`UTF job id: ${data.job_id}`);
    if (data.pytest_command) appendUtfLog(`pytest: ${data.pytest_command}`);
    pollUtfJobBackground(data.job_id);
  } catch (e) {
    setUtfButtonsRunning(false);
    setUtfStatus("Failed", "badge-err");
    appendUtfLog("ERROR: " + e.message);
    showErrorDialog("Launch UTF", e.message);
  }
}

function pollUtfJobBackground(jobId) {
  if (utfPollTimer) clearInterval(utfPollTimer);
  let since = 0;
  let pollErrors = 0;

  utfPollTimer = setInterval(async () => {
    try {
      const job = await api(`/api/utf/${jobId}?since=${since}`, { timeoutMs: API_POLL_TIMEOUT_MS });
      pollErrors = 0;
      if (job.lines?.length) {
        job.lines.forEach((line) => appendUtfLog(line));
        since += job.lines.length;
      }
      if (job.status === "running" || job.status === "queued") {
        setUtfStatus("UTF running on Pi…", "badge-run");
      } else if (job.status === "success") {
        clearInterval(utfPollTimer);
        setUtfStatus("UTF finished", "badge-ok");
        setUtfButtonsRunning(false);
        appendUtfLog("=== UTF launch complete ===");
      } else if (job.status === "failed") {
        clearInterval(utfPollTimer);
        setUtfStatus("UTF failed", "badge-err");
        setUtfButtonsRunning(false);
        if (job.error) appendUtfLog(`ERROR: ${job.error}`);
      } else if (job.status === "stopped") {
        clearInterval(utfPollTimer);
        setUtfStatus("UTF stopped", "badge-warn");
        setUtfButtonsRunning(false);
      }
    } catch (e) {
      pollErrors += 1;
      if (pollErrors === 1 || pollErrors % 5 === 0) {
        appendUtfLog(
          `[utf poll retry ${pollErrors}/${UTF_POLL_MAX_CONSECUTIVE_ERRORS}] ${e.message}`
        );
      }
      setUtfStatus(`UTF running (poll retry ${pollErrors})…`, "badge-run");
      if (pollErrors >= UTF_POLL_MAX_CONSECUTIVE_ERRORS) {
        clearInterval(utfPollTimer);
        setUtfStatus("Poll error", "badge-err");
        setUtfButtonsRunning(false);
        appendUtfLog(`[utf poll error] ${e.message}`);
        appendUtfLog(
          "Polling stopped. UTF may still be running on the Pi — check the terminal where you ran python app.py, or refresh and poll again."
        );
      }
    }
  }, 800);
}

function selectedTestProfile() {
  const id = $("app-select")?.value;
  return appTestProfiles[id] || null;
}

function selectedExampleKind() {
  return $("app-select")?.selectedOptions?.[0]?.dataset?.exampleKind || "ble";
}

function applyProfileDefaults() {
  const profile = selectedTestProfile();
  if (!profile) return;
  if ($("use-passkey")) $("use-passkey").checked = !!profile.use_passkey_default;
  if ($("scan-before-connect")) {
    $("scan-before-connect").checked = !!profile.scan_before_connect_default;
  }
  saveUtfSettings();
}

async function buildFlashTest() {
  const payload = buildPayload();
  const err = validateBuildPayload(payload);
  if (err) {
    showErrorDialog("Build, Flash, Test", err);
    return;
  }
  if (selectedExampleKind() === "coex") {
    await runCoexTest(payload);
    return;
  }
  const { utf_wifi_root, pi_ip, harness, dut_address } = utfPayloadExtras();
  if (!validateUtfSettings({ utf_wifi_root, pi_ip, harness }, "Build, Flash, Test")) return;

  clearLog();
  clearUtfLog();
  serialLineCount = 0;
  showConsoleView("build");
  setStatus("Build, Flash, Test…", "badge-run");
  setWorkflowButtonsDisabled(true);
  setUtfButtonsRunning(true);
  setUtfStatus("Pipeline running…", "badge-run");

  const profile = selectedTestProfile();
  log("=== Build, Flash, Test ===");
  if (profile?.workflow?.length) {
    log(`Workflow: ${profile.workflow.join(" → ")}`);
  }

  try {
    const data = await api("/api/build-flash-test", {
      method: "POST",
      timeoutMs: API_TIMEOUT_MS,
      body: JSON.stringify({
        ...payload,
        utf_wifi_root,
        pi_ip,
        harness,
        use_passkey: $("use-passkey")?.checked || false,
        scan_before_connect: $("scan-before-connect")?.checked || false,
        serial_port: selectedSerialPort(),
        dut_address,
      }),
    });
    currentIntegrationJobId = data.job_id;
    if (data.workflow?.length) {
      log(`Server workflow: ${data.workflow.join(" → ")}`);
    }
    pollIntegrationJob(data.job_id, { fullPipeline: true });
  } catch (e) {
    setWorkflowButtonsDisabled(false);
    setUtfButtonsRunning(false);
    setStatus("Failed", "badge-err");
    setUtfStatus("Failed", "badge-err");
    log("ERROR: " + e.message);
    showErrorDialog("Build, Flash, Test", e.message);
  }
}

async function runCoexTest(payload) {
  const wifiSsid = $("coex-wifi-ssid")?.value?.trim() || "";
  const wifiPassword = $("coex-wifi-password")?.value || "";
  const wifiSecurity = Number($("coex-wifi-security")?.value ?? 2);
  if (!wifiSsid && wifiPassword) {
    showErrorDialog("WLAN + BLE Test", "Enter the Wi-Fi SSID for this password.");
    return;
  }
  if (wifiSsid && wifiSecurity !== 0 && !wifiPassword) {
    showErrorDialog(
      "WLAN + BLE Test",
      "Enter the Wi-Fi password, or select Open security."
    );
    return;
  }
  clearLog();
  showConsoleView("build");
  setStatus("Coexistence test…", "badge-run");
  setWorkflowButtonsDisabled(true);
  log(`=== WLAN + BLE test: ${payload.app_id} ===`);
  log(
    wifiSsid
      ? `Using UI Wi-Fi network: ${wifiSsid}`
      : "Using Wi-Fi settings from coex/<example>_test_scripts/config.local.json"
  );
  const wifiOverrides = wifiSsid
    ? {
        wifi_ssid: wifiSsid,
        wifi_password: wifiPassword,
        wifi_security: wifiSecurity,
      }
    : {};
  try {
    const started = await api("/api/coex/run", {
      method: "POST",
      body: JSON.stringify({
        ...payload,
        ...wifiOverrides,
      }),
    });
    let since = 0;
    while (true) {
      const job = await api(`/api/coex/${started.job_id}?since=${since}`, {
        timeoutMs: API_POLL_TIMEOUT_MS,
      });
      if (job.lines?.length) {
        job.lines.forEach((line) => log(line));
        since += job.lines.length;
      }
      if (job.status === "success") {
        setStatus("Coexistence test passed", "badge-ok");
        setWorkflowButtonsDisabled(false);
        return;
      }
      if (job.status === "failed" || job.status === "stopped") {
        throw new Error(job.error || `Coexistence test ${job.status}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 800));
    }
  } catch (e) {
    setStatus("Coexistence test failed", "badge-err");
    setWorkflowButtonsDisabled(false);
    log("ERROR: " + e.message);
    showErrorDialog("WLAN + BLE Test", e.message);
  }
}

async function startConnection() {
  const payload = buildPayload();
  const err = validateBuildPayload(payload);
  if (err) {
    showErrorDialog("Start Connection", err);
    return;
  }
  const { pi_ip, dut_address } = utfPayloadExtras();
  if (!pi_ip) {
    showErrorDialog("Start Connection", "Raspberry Pi IP is required");
    return;
  }

  showConsoleView("build");
  clearLog();
  setStatus("Starting connection…", "badge-run");
  setWorkflowButtonsDisabled(true);
  const scanFirst = $("scan-before-connect")?.checked || false;
  log(`=== Start Connection: ${payload.app_id} → Pi ${pi_ip} (passkey=${$("use-passkey")?.checked ? "yes" : "no"}, scan_first=${scanFirst}) ===`);
  if ($("use-passkey")?.checked) {
    log("SMP: connect (bond=true) → parse passkey from serial → POST /ble/passkey → enable notifications");
  } else {
    log("No SMP: connect (bond=false) → enable notifications. For SMP use Passkey connect (SMP) debug button.");
  }
  log("Ensure step 1 (Build & Flash) opened serial and step 2 (Launch UTF) is running on the Pi.");

  try {
    const data = await api("/api/start-connection", {
      method: "POST",
      body: JSON.stringify({
        ...payload,
        pi_ip,
        use_passkey: $("use-passkey")?.checked || false,
        serial_port: selectedSerialPort(),
        scan_before_connect: scanFirst,
        dut_address,
      }),
    });
    currentIntegrationJobId = data.job_id;
    pollIntegrationJob(data.job_id);
  } catch (e) {
    setWorkflowButtonsDisabled(false);
    setStatus("Failed", "badge-err");
    log("ERROR: " + e.message);
    showErrorDialog("Start Connection", e.message);
  }
}

function bleDutAddress() {
  return $("ble-dut-address")?.value?.trim().toUpperCase() || "";
}

function bleDebugRequestBody(extra = {}) {
  const payload = buildPayload();
  const { pi_ip } = utfPayloadExtras();
  return {
    ...payload,
    pi_ip,
    address: bleDutAddress() || undefined,
    use_passkey: $("use-passkey")?.checked || false,
    serial_port: selectedSerialPort(),
    ...extra,
  };
}

async function runBleDebugStep(step, label, extra = {}, timeoutMs = API_POLL_TIMEOUT_MS) {
  const { pi_ip } = utfPayloadExtras();
  if (!pi_ip) {
    showErrorDialog(label, "Raspberry Pi IP is required");
    return;
  }
  showConsoleView("build");
  setStatus(label, "badge-run");
  log(`=== BLE debug: ${label} → Pi ${pi_ip} ===`);

  try {
    const out = await api("/api/ble-debug/step", {
      method: "POST",
      timeoutMs,
      body: JSON.stringify(bleDebugRequestBody({ step, ...extra })),
    });
    (out.logs || []).forEach((line) => log(line));
    if (out.result) {
      log("--- result ---");
      log(JSON.stringify(out.result, null, 2));
    }
    if (out.ok) {
      setStatus(label + " OK", "badge-ok");
      if (out.result?.address) {
        $("ble-dut-address").value = out.result.address;
      }
    } else {
      setStatus(label + " failed", "badge-err");
      if (out.error) showErrorDialog(label, out.error);
    }
  } catch (e) {
    setStatus("Failed", "badge-err");
    log("ERROR: " + e.message);
    showErrorDialog(label, e.message);
  }
}

async function bleParseAddressFromSerial() {
  const existing = bleDutAddress();
  if (existing) {
    showConsoleView("build");
    log(`Using configured DUT address: ${existing}`);
    return;
  }
  await runBleDebugStep("parse_address", "Parse address", {}, BLE_STEP_TIMEOUT_MS);
}

async function bleScan() {
  if (!bleDutAddress()) {
    showErrorDialog("Scan", "Enter DUT BLE address or click From serial");
    return;
  }
  await runBleDebugStep("scan", "Scan");
}

async function bleConnectDirect() {
  if (!bleDutAddress()) {
    showErrorDialog("Connect", "Enter DUT BLE address or click From serial");
    return;
  }
  await runBleDebugStep("connect", "Connect (direct)", { scan_before_connect: false });
}

async function blePasskeyConnect() {
  const err = validateBuildPayload(buildPayload());
  if (err) {
    showErrorDialog("Passkey connect", err);
    return;
  }
  if (!bleDutAddress()) {
    showErrorDialog("Passkey connect", "Enter DUT BLE address or click From serial");
    return;
  }
  await runBleDebugStep("passkey_connect", "Passkey connect (SMP)", {
    scan_before_connect: false,
  });
}

async function bleConnectAfterScan() {
  if (!bleDutAddress()) {
    showErrorDialog("Connect", "Enter DUT BLE address or click From serial");
    return;
  }
  await runBleDebugStep("connect", "Connect (scan first)", { scan_before_connect: true });
}

async function bleStatus() {
  await runBleDebugStep("status", "Status");
}

async function bleEnableNotifications() {
  const err = validateBuildPayload(buildPayload());
  if (err) {
    showErrorDialog("Enable notifications", err);
    return;
  }
  await runBleDebugStep("enable_notifications", "Enable notifications");
}

async function bleGetNotifications() {
  await runBleDebugStep("notifications", "Get notifications");
}

function pollIntegrationJob(jobId, opts = {}) {
  const fullPipeline = opts.fullPipeline === true;
  if (integrationPollTimer) clearInterval(integrationPollTimer);
  let lastLogLen = 0;
  let utfSince = 0;

  integrationPollTimer = setInterval(async () => {
    try {
      const url = fullPipeline
        ? `/api/integration/${jobId}?utf_since=${utfSince}`
        : `/api/integration/${jobId}`;
      const job = await api(url, { timeoutMs: INTEGRATION_POLL_TIMEOUT_MS });
      if (job.logs?.length > lastLogLen) {
        job.logs.slice(lastLogLen).forEach((line) => log(line));
        lastLogLen = job.logs.length;
        $("log-output").scrollTop = $("log-output").scrollHeight;
      }

      if (fullPipeline && job.utf_lines?.length) {
        job.utf_lines.forEach((line) => appendUtfLog(line));
        utfSince += job.utf_lines.length;
        if (job.utf_job_id) currentUtfJobId = job.utf_job_id;
      }

      const phase = job.phase || job.status;
      const phaseLabel = {
        launch_utf: "Launch UTF on Pi…",
        wait_pi_health: "Waiting for Pi BLE HTTP…",
        build_flash: "Build & flash…",
        "wait-pi": "Waiting for Pi…",
        serial: "Serial / DUT address…",
        orchestrate: "BLE connect…",
        done: "Done",
      }[phase] || phase;
      setStatus(phaseLabel, job.status === "running" ? "badge-run" : "");

      if (fullPipeline) {
        setUtfStatus(phaseLabel, job.status === "running" ? "badge-run" : "");
      }

      if (job.status === "success") {
        clearInterval(integrationPollTimer);
        setStatus(fullPipeline ? "Test passed" : "Connection passed", "badge-ok");
        if (fullPipeline) {
          setUtfStatus("Pipeline finished", "badge-ok");
          setUtfButtonsRunning(false);
          // Backend already appends === Build, Flash, Test PASSED ===
        } else {
          log("=== Connection test PASSED ===");
        }
        setWorkflowButtonsDisabled(false);
      } else if (job.status === "failed") {
        clearInterval(integrationPollTimer);
        setStatus("Failed", "badge-err");
        if (fullPipeline) {
          setUtfStatus("Pipeline failed", "badge-err");
          setUtfButtonsRunning(false);
        }
        setWorkflowButtonsDisabled(false);
        if (job.error) {
          showErrorDialog(fullPipeline ? "Build, Flash, Test" : "Connection Failed", job.error);
        }
      }
    } catch (e) {
      clearInterval(integrationPollTimer);
      setStatus("Error", "badge-err");
      if (fullPipeline) {
        setUtfStatus("Error", "badge-err");
        setUtfButtonsRunning(false);
      }
      setWorkflowButtonsDisabled(false);
      log("Poll error: " + e.message);
    }
  }, 1000);
}

function pollConnectionJob(jobId) {
  pollIntegrationJob(jobId);
}

async function stopUtfTests() {
  if (currentUtfJobId) {
    try {
      await api(`/api/utf/${currentUtfJobId}/stop`, { method: "POST", body: "{}" });
      setUtfStatus("Stopped", "badge-warn");
      setUtfButtonsRunning(false);
    } catch (e) {
      showErrorDialog("UTF Tests", e.message);
    }
  }
  // Also tear down Pi BLE HTTP so /health is not left green for the next run.
  await stopPiBleServer("stopped from UTF console");
}

async function stopPiBleServer(reason = "stopped from Build Studio") {
  const { pi_ip } = utfPayloadExtras();
  if (!pi_ip) {
    showErrorDialog("Stop Pi BLE Server", "Set UTF Target (Pi IP) first.");
    return;
  }
  try {
    log(`=== Stop Pi BLE Server (${pi_ip}) ===`);
    setStatus("Stopping Pi BLE…", "badge-run");
    const result = await api("/api/pi/abort-ble-http", {
      method: "POST",
      body: JSON.stringify({ pi_ip, reason }),
      timeoutMs: 60000,
    });
    (result.logs || []).forEach((line) => log(line));
    if (result.skipped) {
      log("Pi BLE HTTP was not running.");
      setStatus("Idle", "badge-ok");
    } else if (result.server_down || result.ok) {
      log("Pi BLE HTTP aborted; pytest will report failure.");
      setStatus("Pi BLE stopped", "badge-warn");
      setUtfStatus("Aborted", "badge-warn");
    } else {
      log("Abort may be incomplete: " + (result.error || JSON.stringify(result)));
      setStatus("Abort incomplete", "badge-err");
    }
  } catch (e) {
    showErrorDialog("Stop Pi BLE Server", e.message);
    setStatus("Error", "badge-err");
  }
}

function pollUtfJob(jobId) {
  if (utfPollTimer) clearInterval(utfPollTimer);
  utfPollTimer = setInterval(async () => {
    try {
      const job = await api(`/api/utf/${jobId}`);
      $("utf-log-output").textContent = job.logs.join("\n") + "\n";
      $("utf-log-output").scrollTop = $("utf-log-output").scrollHeight;

      if (job.status === "running") {
        setUtfStatus("Running…", "badge-run");
      } else if (job.status === "success") {
        clearInterval(utfPollTimer);
        setUtfStatus("Success", "badge-ok");
        setUtfButtonsRunning(false);
      } else if (job.status === "failed") {
        clearInterval(utfPollTimer);
        setUtfStatus("Failed", "badge-err");
        setUtfButtonsRunning(false);
        if (job.error) showErrorDialog("UTF Tests Failed", job.error);
      } else if (job.status === "stopped") {
        clearInterval(utfPollTimer);
        setUtfStatus("Stopped", "badge-warn");
        setUtfButtonsRunning(false);
      }
    } catch (e) {
      clearInterval(utfPollTimer);
      setUtfStatus("Error", "badge-err");
      setUtfButtonsRunning(false);
    }
  }, 800);
}

function updateAppTestHint() {
  const el = $("app-test-hint");
  const wfEl = $("workflow-hint");
  const sel = $("app-select");
  if (!el || !sel) return;
  const opt = sel.selectedOptions?.[0];
  const testFn = opt?.dataset?.testFunction;
  const profile = selectedTestProfile();
  const kind = selectedExampleKind();
  el.textContent = testFn
    ? `${kind === "coex" ? "Coexistence script" : "UTF test"}: ${testFn}`
    : kind === "coex"
      ? "No automated coexistence test is registered for this example yet."
      : "Select an application to see its UTF test case.";
  if (wfEl) {
    wfEl.textContent = profile?.workflow?.length
      ? `Pipeline: ${profile.workflow.join(" → ")}`
      : "";
  }
  const runButton = $("btn-build-flash-test");
  if (runButton) {
    runButton.textContent = kind === "coex"
      ? "Run WLAN + BLE Test"
      : "Build, Flash, Test";
    runButton.disabled = kind === "coex" && profile?.supported === false;
  }
  updateUtfHint();
}

// Tabs
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $(tab.dataset.tab).classList.add("active");
  });
});

function bind(id, event, fn) {
  const el = $(id);
  if (el) el.addEventListener(event, fn);
}

bind("target-select", "change", updateBoards);
bind("btn-config", "click", openConfig);
bind("nav-console-build", "click", () => showConsoleView("build"));
bind("nav-console-serial", "click", () => showSerialView());
bind("nav-console-utf", "click", () => showUtfView());
bind("nav-console-build-side", "click", () => showConsoleView("build"));
bind("nav-console-serial-side", "click", () => showSerialView());
bind("nav-console-utf-side", "click", () => showUtfView());
bind("btn-utf-stop-console", "click", stopUtfTests);
bind("btn-utf-back-build", "click", () => showConsoleView("build"));
bind("utf-workspace-root", "change", saveUtfSettings);
bind("utf-target", "change", saveUtfSettings);
bind("utf-harness", "change", saveUtfSettings);
bind("use-passkey", "change", saveUtfSettings);
bind("ble-dut-address", "change", saveUtfSettings);
bind("app-select", "change", () => {
  applyProfileDefaults();
  updateAppTestHint();
});
bind("btn-validate-sdk", "click", validateSdk);
bind("btn-download-sdk", "click", downloadSdk);
bind("btn-build-flash-test", "click", buildFlashTest);
bind("btn-prebuild-configurations", "click", applyPrebuildConfigurations);
bind("btn-stop-pi-ble", "click", () => stopPiBleServer());
bind("btn-build", "click", () => startBuild(false));
bind("btn-build-flash", "click", startBuildFlash);
bind("btn-launch-utf", "click", launchUtf);
bind("btn-start-connection", "click", startConnection);
bind("btn-ble-parse-address", "click", bleParseAddressFromSerial);
bind("btn-ble-scan", "click", bleScan);
bind("btn-ble-connect", "click", bleConnectDirect);
bind("btn-ble-passkey-connect", "click", blePasskeyConnect);
bind("btn-ble-connect-scan", "click", bleConnectAfterScan);
bind("btn-ble-status", "click", bleStatus);
bind("btn-ble-enable-notify", "click", bleEnableNotifications);
bind("btn-ble-get-notify", "click", bleGetNotifications);
bind("btn-flash", "click", flash);
bind("btn-refresh-adapters", "click", loadAdapters);
bind("btn-device-info", "click", getDeviceInfo);
bind("btn-device-recover", "click", recoverDevice);
bind("btn-serial-connect", "click", startSerialMonitor);
bind("btn-back-build", "click", () => showConsoleView("build"));
bind("serial-port", "change", () => {
  const v = $("serial-port")?.value;
  if ($("serial-port-view") && v) $("serial-port-view").value = v;
});
bind("ble-root", "change", loadApps);
bind("sdk-local-path", "change", loadApps);
bind("sdk-select", "change", () => {
  const sel = $("sdk-select");
  if (sel.value) $("sdk-local-path").value = sel.value;
  loadApps();
});

async function init() {
  log("WiseConnect Build Studio starting…");
  log("Server: " + window.location.origin);
  await loadUtfSettings();
  await loadSerialPorts().catch(() => {});
  const autoBuild = applyUrlParams();
  await Promise.allSettled([
    loadTools(),
    loadBoards(),
    loadSdks(),
    loadApps(),
    loadAdapters(),
  ]);
  const params = new URLSearchParams(window.location.search);
  if (params.get("app_id")) $("app-select").value = params.get("app_id");
  updateAppTestHint();
  applyProfileDefaults();
  log("Ready — set SDK, app, Pi IP, then click Build, Flash, Test.");
  setStatus("Idle", "");
  if (autoBuild) buildFlashTest();
}

window.addEventListener("message", handleConfigMessage);

// Populate boards immediately from defaults (before API)
updateBoards();

init();
