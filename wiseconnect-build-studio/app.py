"""WiseConnect Build Studio — mini Simplicity Studio for BLE CLI builds."""

from __future__ import annotations

import threading
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from app_catalog import apps_as_dicts
from build_engine import (
    device_info,
    device_recover,
    flash_build,
    get_job,
    list_adapters,
    list_jobs,
    run_build,
)
from config import (
    BOARDS,
    DEFAULT_BOARD,
    DEFAULT_UTF_EXECUTOR,
    DEFAULT_UTF_HARNESS,
    DEFAULT_UTF_TARGET,
    DEFAULT_UTF_WORKSPACE,
    HEALTH_TIMEOUT_SEC,
    HOST,
    MAC_PARSE_TIMEOUT_SEC,
    PI_HTTP_PORT,
    PORT,
    TOOLCHAINS,
    WORKSPACE,
)
from header_config import list_app_headers, read_header, save_header
from prebuild_config import apply_prebuild_configurations
from sdk_manager import (
    ble_root_for,
    default_ble_root,
    default_sdk_root,
    find_wiseconnect_root,
    list_cached_sdks,
    prepare_sdk_from_urls,
    validate_and_trust,
    validate_local_sdk,
)
from serial_monitor import (
    DEFAULT_BAUD,
    get_lines,
    guess_vcom_port,
    list_serial_ports,
    serial_status,
    start_serial,
    stop_serial,
)
from dut_serial_checklist import (
    extract_checklist_lines,
    filter_noise_lines,
    resolve_checklist_kind,
)
from tool_finder import tool_status
from utf_runner import get_utf_job, list_utf_jobs, run_utf_tests, stop_utf_job
from coex_runner import (
    get_coex_job,
    list_coex_jobs,
    run_coex_test,
    stop_coex_job,
)
from test_orchestrator import (
    abort_pi_ble_http_server,
    get_integration_job,
    list_integration_jobs,
    run_ble_debug_step,
    run_build_flash_test,
    run_start_connection,
)

app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def disable_cache(response):
    if request.path.startswith("/static/") or request.path in ("/", "/config"):
        response.cache_control.no_store = True
    return response


_download_jobs: dict = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/config")
def config_page():
    return render_template("config.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "workspace": str(WORKSPACE)})


@app.get("/api/tools")
def tools():
    refresh = request.args.get("refresh", "").lower() in ("1", "true", "yes")
    try:
        status = tool_status(refresh=refresh)
        status["ok"] = True
        return jsonify(status)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc), "ready": False, "llvm_ready": False})


@app.get("/api/apps")
def apps():
    ble_root = request.args.get("ble_root")
    sdk_root = request.args.get("sdk_root")

    if not ble_root and sdk_root:
        wiseconnect = find_wiseconnect_root(Path(sdk_root))
        candidate = ble_root_for(wiseconnect)
        if candidate:
            ble_root = str(candidate)

    if not ble_root:
        discovered = default_ble_root()
        ble_root = str(discovered) if discovered else ""

    exists = bool(ble_root) and Path(ble_root).is_dir()
    app_list = apps_as_dicts(Path(ble_root)) if exists else []
    return jsonify({
        "apps": app_list,
        "ble_root": ble_root,
        "count": len(app_list),
        "exists": exists,
        "error": None if exists else (
            "No BLE examples folder found. Select an SDK root that contains "
            "extension/wiseconnect, or set WISECONNECT_BLE_EXAMPLES."
        ),
    })


@app.get("/api/boards")
def boards():
    return jsonify(BOARDS)


@app.get("/api/toolchains")
def toolchains():
    return jsonify(TOOLCHAINS)


@app.get("/api/adapters")
def adapters():
    try:
        return jsonify(list_adapters())
    except Exception as exc:
        return jsonify({"error": str(exc), "adapters": [], "device_count": 0}), 500


@app.get("/api/device/info")
def device_info_route():
    serial = request.args.get("serial")
    try:
        result = device_info(adapter_serial=serial)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/device/recover")
def device_recover_route():
    data = request.get_json(force=True) or {}
    try:
        result = device_recover(adapter_serial=data.get("adapter_serial"))
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500



@app.get("/api/utf/defaults")
def utf_defaults():
    return jsonify({
        "workspace_root": str(DEFAULT_UTF_WORKSPACE) if DEFAULT_UTF_WORKSPACE else "",
        "executor_dir": str(DEFAULT_UTF_EXECUTOR) if DEFAULT_UTF_EXECUTOR else "",
        "target": DEFAULT_UTF_TARGET,
        "harness": DEFAULT_UTF_HARNESS,
        "pi_http_port": PI_HTTP_PORT,
        "mac_parse_timeout_sec": MAC_PARSE_TIMEOUT_SEC,
        "health_timeout_sec": HEALTH_TIMEOUT_SEC,
    })


def _dut_address_from_request(data: dict) -> str | None:
    raw = (data.get("dut_address") or data.get("address") or "").strip()
    return raw or None


@app.post("/api/utf/run")
def utf_run():
    data = request.get_json(force=True) or {}
    workspace = (data.get("utf_wifi_root") or data.get("workspace_root") or "").strip()
    executor_dir = (data.get("executor_dir") or "").strip()
    if not executor_dir and workspace:
        executor_dir = str(Path(workspace).expanduser() / "executor")
    target = (data.get("target") or "").strip()
    harness = (data.get("harness") or "").strip()
    pytest_command = (data.get("pytest_command") or "").strip() or None
    app_id = (data.get("app_id") or "").strip()
    if not pytest_command and app_id:
        from app_test_catalog import pytest_command as build_pytest_command
        pytest_command = build_pytest_command(app_id)
    if not executor_dir:
        return jsonify({"error": "executor_dir or utf_wifi_root required"}), 400
    docker_flags = None
    if app_id in ("ble_hid_on_gatt", "ble_hid_on_gatt_client") or (
        pytest_command and "ble_hid_on_gatt" in pytest_command
    ):
        hid_app = app_id if app_id in (
            "ble_hid_on_gatt",
            "ble_hid_on_gatt_client",
        ) else "ble_hid_on_gatt"
        docker_flags = f"-e BLE_BLUEZ_NOPPLUGIN_INPUT=1, -e BLE_APP_ID={hid_app}"
    elif app_id == "ble_heart_rate_profile_client" or (
        pytest_command and "ble_heart_rate_profile_client" in pytest_command
    ):
        docker_flags = "-e BLE_APP_ID=ble_heart_rate_profile_client"
    try:
        job_id = run_utf_tests(
            executor_dir,
            target,
            harness,
            pytest_command=pytest_command,
            docker_flags=docker_flags,
        )
        return jsonify({"job_id": job_id})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/utf")
def utf_jobs():
    return jsonify({"jobs": list_utf_jobs()})


@app.get("/api/utf/<job_id>")
def utf_status(job_id):
    job = get_utf_job(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    since = request.args.get("since", default=0, type=int)
    if since < 0:
        since = 0
    logs = job.logs
    total = len(logs)
    lines = logs[since:] if since <= total else []
    # Cap burst size so docker build output cannot stall the HTTP response.
    max_lines = request.args.get("max_lines", default=500, type=int)
    if max_lines > 0 and len(lines) > max_lines:
        lines = lines[:max_lines]
    return jsonify({
        "id": job.id,
        "status": job.status,
        "error": job.error,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "config": job.config,
        "total": total,
        "lines": lines,
    })


@app.post("/api/utf/<job_id>/stop")
def utf_stop(job_id):
    try:
        return jsonify(stop_utf_job(job_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 404


@app.post("/api/coex/run")
def coex_run():
    data = request.get_json(force=True) or {}
    app_id = (data.get("app_id") or "").strip()
    if not app_id:
        return jsonify({"error": "app_id is required"}), 400
    try:
        studio_overrides = {
            "sdk_root": data.get("sdk_root"),
            "examples_root": data.get("ble_root") or data.get("examples_root"),
            "board": data.get("board"),
            "toolchain": data.get("toolchain"),
            "adapter_serial": data.get("adapter_serial"),
        }
        wifi_overrides = {
            "ssid": data.get("wifi_ssid"),
            "password": data.get("wifi_password"),
            "security": data.get("wifi_security"),
        }
        return jsonify({
            "job_id": run_coex_test(
                app_id,
                studio_overrides=studio_overrides,
                wifi_overrides=wifi_overrides,
            )
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/coex")
def coex_jobs():
    return jsonify({"jobs": list_coex_jobs()})


@app.get("/api/coex/<job_id>")
def coex_status(job_id):
    job = get_coex_job(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    since = max(0, request.args.get("since", default=0, type=int))
    payload = job.to_dict()
    payload["total"] = len(job.logs)
    payload["lines"] = job.logs[since:]
    payload.pop("logs", None)
    return jsonify(payload)


@app.post("/api/coex/<job_id>/stop")
def coex_stop(job_id):
    try:
        return jsonify(stop_coex_job(job_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 404


@app.post("/api/pi/abort-ble-http")
def pi_abort_ble_http():
    """
    Force-stop the Pi BLE RasPi HTTP pytest server (POST /ble/orchestration/abort)
    and wait until /health is down. Use before relaunch or after Build Studio errors.
    """
    data = request.get_json(force=True) or {}
    pi_ip = (data.get("pi_ip") or data.get("utf_target") or "").strip()
    if not pi_ip:
        return jsonify({"error": "pi_ip is required"}), 400
    reason = (data.get("reason") or "aborted from Build Studio").strip()
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)

    try:
        result = abort_pi_ble_http_server(pi_ip, reason=reason, log=_log)
        return jsonify({**result, "logs": logs})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc), "logs": logs}), 500


@app.get("/api/integration")
def integration_jobs():
    return jsonify({"jobs": list_integration_jobs()})


@app.get("/api/integration/<job_id>")
def integration_status(job_id):
    job = get_integration_job(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    payload = job.to_dict()
    since_utf = request.args.get("utf_since", type=int, default=0)
    if job.utf_job_id:
        utf = get_utf_job(job.utf_job_id)
        if utf:
            payload["utf_job_id"] = job.utf_job_id
            payload["utf_status"] = utf.status
            payload["utf_log_total"] = len(utf.logs)
            if since_utf >= 0:
                payload["utf_lines"] = utf.logs[since_utf:]
    return jsonify(payload)


@app.post("/api/build-flash-test")
def build_flash_test():
    """Full pipeline using per-app workflow from app_test_catalog (UTF → Pi ready → flash → connect)."""
    data = request.get_json(force=True) or {}
    try:
        args = _build_request(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    utf_wifi_root = (data.get("utf_wifi_root") or data.get("workspace_root") or "").strip()
    if not utf_wifi_root and DEFAULT_UTF_WORKSPACE:
        utf_wifi_root = str(DEFAULT_UTF_WORKSPACE)
    pi_ip = (data.get("pi_ip") or data.get("utf_target") or "").strip()
    harness = (data.get("harness") or DEFAULT_UTF_HARNESS).strip()
    if not utf_wifi_root:
        return jsonify({"error": "utf_wifi_root is required"}), 400
    if not pi_ip:
        return jsonify({"error": "pi_ip (Raspberry Pi target) is required"}), 400

    use_passkey = data.get("use_passkey")
    if use_passkey is not None:
        use_passkey = bool(use_passkey)
    scan_before = data.get("scan_before_connect")
    if scan_before is not None:
        scan_before = bool(scan_before)

    try:
        job_id = run_build_flash_test(
            app_id=args["app_id"],
            target=args["target"],
            board=args["board"],
            toolchain=args["toolchain"],
            sdk_root=args["sdk_root"],
            ble_root=args.get("ble_root"),
            pi_ip=pi_ip,
            utf_wifi_root=utf_wifi_root,
            harness=harness,
            use_passkey=use_passkey,
            serial_port=(data.get("serial_port") or "").strip() or None,
            scan_before_connect=scan_before,
            adapter_serial=(data.get("adapter_serial") or "").strip() or None,
            dut_address=_dut_address_from_request(data),
        )
        from app_test_catalog import test_profile

        return jsonify({"job_id": job_id, "workflow": test_profile(args["app_id"]).get("workflow")})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/launch-utf")
def launch_utf():
    """Launch UTF on Raspberry Pi only (docker deploy + app-specific pytest)."""
    data = request.get_json(force=True) or {}
    try:
        args = _build_request(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    utf_wifi_root = (data.get("utf_wifi_root") or data.get("workspace_root") or "").strip()
    if not utf_wifi_root and DEFAULT_UTF_WORKSPACE:
        utf_wifi_root = str(DEFAULT_UTF_WORKSPACE)
    pi_ip = (data.get("pi_ip") or data.get("utf_target") or "").strip()
    harness = (data.get("harness") or DEFAULT_UTF_HARNESS).strip()
    if not utf_wifi_root:
        return jsonify({"error": "utf_wifi_root is required"}), 400
    if not pi_ip:
        return jsonify({"error": "pi_ip (Raspberry Pi target) is required"}), 400

    executor_dir = str(Path(utf_wifi_root).expanduser().resolve() / "executor")
    from app_test_catalog import pytest_command as build_pytest_command

    try:
        app_id = str(args.get("app_id") or "")
        docker_flags = (
            "-e BLE_BLUEZ_NOPPLUGIN_INPUT=1, -e BLE_APP_ID=ble_hid_on_gatt"
            if app_id == "ble_hid_on_gatt"
            else "-e BLE_BLUEZ_NOPPLUGIN_INPUT=1, -e BLE_APP_ID=ble_hid_on_gatt_client"
            if app_id == "ble_hid_on_gatt_client"
            else "-e BLE_APP_ID=ble_heart_rate_profile_client"
            if app_id == "ble_heart_rate_profile_client"
            else None
        )
        job_id = run_utf_tests(
            executor_dir,
            pi_ip,
            harness,
            pytest_command=build_pytest_command(app_id),
            docker_flags=docker_flags,
        )
        return jsonify({"job_id": job_id, "pytest_command": build_pytest_command(args["app_id"])})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/start-connection")
def start_connection():
    """Parse DUT serial and drive Pi BLE HTTP connect / passkey / notifications."""
    data = request.get_json(force=True) or {}
    try:
        args = _build_request(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    pi_ip = (data.get("pi_ip") or data.get("utf_target") or "").strip()
    if not pi_ip:
        return jsonify({"error": "pi_ip (Raspberry Pi target) is required"}), 400

    try:
        job_id = run_start_connection(
            app_id=args["app_id"],
            pi_ip=pi_ip,
            use_passkey=bool(data.get("use_passkey", False)),
            serial_port=(data.get("serial_port") or "").strip() or None,
            scan_before_connect=bool(data.get("scan_before_connect", False)),
            dut_address=_dut_address_from_request(data),
        )
        return jsonify({"job_id": job_id})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/ble-debug/step")
def ble_debug_step():
    """Single Pi BLE HTTP step for manual debugging (scan / connect / status / …)."""
    data = request.get_json(force=True) or {}
    pi_ip = (data.get("pi_ip") or data.get("utf_target") or "").strip()
    if not pi_ip:
        return jsonify({"error": "pi_ip (Raspberry Pi target) is required"}), 400

    step = (data.get("step") or "").strip()
    if not step:
        return jsonify({"error": "step is required (scan, connect, status, enable_notifications, …)"}), 400

    app_id = (data.get("app_id") or "").strip() or None
    if not app_id:
        try:
            app_id = _build_request(data)["app_id"]
        except Exception:
            app_id = None

    conn_params = _conn_params_from_request(data, app_id)

    payload = run_ble_debug_step(
        step=step,
        pi_ip=pi_ip,
        app_id=app_id,
        address=(data.get("address") or data.get("dut_address") or "").strip() or None,
        use_passkey=bool(data.get("use_passkey", False)),
        passkey=(data.get("passkey") or "").strip() or None,
        scan_timeout=int(data.get("scan_timeout") or 15),
        serial_port=(data.get("serial_port") or "").strip() or None,
        scan_before_connect=bool(data.get("scan_before_connect", False)),
        conn_params=conn_params,
    )
    status = 200 if payload.get("ok") else 400
    return jsonify(payload), status


@app.get("/api/app/headers")
def app_headers():
    app_id = request.args.get("app_id")
    if not app_id:
        return jsonify({"error": "app_id required"}), 400
    ble_root = request.args.get("ble_root")
    target = request.args.get("target")
    toolchain = request.args.get("toolchain")
    try:
        headers = list_app_headers(
            app_id,
            Path(ble_root) if ble_root else None,
            target=target,
            toolchain=toolchain,
        )
        return jsonify({
            "headers": headers,
            "app_id": app_id,
            "target": target,
            "toolchain": toolchain,
            "count": len(headers),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/app/header")
def app_header_read():
    app_id = request.args.get("app_id")
    rel_path = request.args.get("path")
    if not app_id or not rel_path:
        return jsonify({"error": "app_id and path required"}), 400
    ble_root = request.args.get("ble_root")
    try:
        return jsonify(read_header(app_id, rel_path, Path(ble_root) if ble_root else None))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.put("/api/app/header")
def app_header_save():
    data = request.get_json(force=True)
    app_id = data.get("app_id")
    rel_path = data.get("path")
    content = data.get("content")
    if not app_id or not rel_path or content is None:
        return jsonify({"error": "app_id, path, and content required"}), 400
    ble_root = data.get("ble_root")
    try:
        return jsonify(save_header(app_id, rel_path, content, Path(ble_root) if ble_root else None))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/serial/ports")
def serial_ports():
    try:
        ports = list_serial_ports()
        suggested = guess_vcom_port()
        return jsonify({"ports": ports, "suggested": suggested, "default_baud": DEFAULT_BAUD})
    except Exception as exc:
        return jsonify({"error": str(exc), "ports": [], "suggested": None}), 500


@app.get("/api/serial/status")
def serial_status_route():
    return jsonify(serial_status())


@app.post("/api/serial/start")
def serial_start():
    data = request.get_json(force=True) or {}
    port = data.get("port")
    baud = int(data.get("baud", DEFAULT_BAUD))
    if not port:
        return jsonify({"error": "port required"}), 400
    try:
        return jsonify(start_serial(port, baud))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/serial/stop")
def serial_stop():
    return jsonify(stop_serial())


@app.get("/api/serial/lines")
def serial_lines():
    since = int(request.args.get("since", 0))
    filt = (request.args.get("filter") or "").strip().lower()
    kind = resolve_checklist_kind(
        app_id=request.args.get("app_id"),
        kind=request.args.get("kind"),
    )
    if filt == "checklist" and kind:
        lines = extract_checklist_lines(since, kind=kind)
        return jsonify(
            {
                "lines": lines,
                "total": len(lines),
                "since": since,
                "mode": "checklist",
                "kind": kind,
            }
        )
    payload = get_lines(since)
    if filt == "clean":
        payload["lines"] = filter_noise_lines(payload.get("lines") or [])
        payload["mode"] = "clean"
    return jsonify(payload)


@app.get("/api/sdks")
def sdks():
    local = request.args.get("local")
    if local:
        try:
            return jsonify(validate_local_sdk(Path(local)))
        except Exception as exc:
            return jsonify({"valid": False, "error": str(exc)}), 400

    default = default_sdk_root()
    ble_root = default_ble_root()
    return jsonify({
        "sdks": list_cached_sdks(),
        "default": str(default) if default else "",
        "ble_root": str(ble_root) if ble_root else "",
    })


@app.post("/api/sdk/validate")
def sdk_validate():
    """
    Validate button flow:

    1. Check the user-entered SDK path has simplicity_sdk.slcs + wiseconnect
    2. Run ``slc signature trust`` for both packages
    3. Return ble_root so the UI can load examples
    """
    data = request.get_json(force=True) or {}
    path = (data.get("sdk_root") or data.get("path") or "").strip()
    if not path:
        return jsonify({"valid": False, "error": "sdk_root is required"}), 400

    logs: list = []

    def log(msg: str) -> None:
        logs.append(msg)

    try:
        info = validate_and_trust(Path(path), log=log)
        info["logs"] = logs
        return jsonify(info)
    except Exception as exc:
        return jsonify({
            "valid": False,
            "trusted": False,
            "error": str(exc),
            "logs": logs,
        }), 400


@app.post("/api/sdk/download")
def sdk_download():
    data = request.get_json(force=True)
    gecko_url = data.get("gecko_url", "").strip()
    wise_url = data.get("wiseconnect_url", "").strip()
    name = data.get("name", "downloaded_sdk").strip() or "downloaded_sdk"
    if not gecko_url or not wise_url:
        return jsonify({"error": "gecko_url and wiseconnect_url are required"}), 400

    job_id = name
    _download_jobs[job_id] = {"status": "running", "logs": []}

    def worker():
        job = _download_jobs[job_id]

        def log(msg):
            job["logs"].append(msg)

        try:
            info = prepare_sdk_from_urls(gecko_url, wise_url, name, log)
            job["status"] = "success"
            job["sdk"] = info
        except Exception as exc:
            job["status"] = "failed"
            job["error"] = str(exc)
            log(f"ERROR: {exc}")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.get("/api/sdk/download/<job_id>")
def sdk_download_status(job_id):
    job = _download_jobs.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


def _conn_params_from_request(data: dict, app_id: str | None) -> dict:
    from app_test_catalog import connect_conn_params

    override: dict = {}
    raw = data.get("conn_params")
    if isinstance(raw, dict):
        override.update(raw)
    for key in ("min_conn_interval", "max_conn_interval", "conn_latency", "supervision_timeout"):
        if data.get(key) is not None:
            override[key] = data[key]
    return connect_conn_params(app_id, override or None)


def _build_request(data: dict) -> dict:
    """Validate a build payload, filling in defaults that can be discovered."""
    for key in ("app_id", "target", "toolchain"):
        if not data.get(key):
            raise ValueError(f"Missing field: {key}")

    target = data["target"]
    board = data.get("board") or DEFAULT_BOARD.get(target)
    if not board:
        raise ValueError(f"Missing field: board (no default for target '{target}')")

    sdk_root = data.get("sdk_root") or ""
    if not sdk_root:
        discovered = default_sdk_root()
        if not discovered:
            raise ValueError(
                "No SDK root given and none could be discovered. Set the SDK root "
                "in the UI, or install one with 'slt install pkg.slt'."
            )
        sdk_root = str(discovered)

    sdk = validate_local_sdk(Path(sdk_root))
    return {
        "app_id": data["app_id"],
        "target": target,
        "board": board,
        "toolchain": data["toolchain"],
        "sdk_root": sdk["sdk_root"],
        "ble_root": data.get("ble_root") or sdk.get("ble_root"),
        "mqtt_broker_ip": data.get("mqtt_broker_ip") or None,
        "aws_mqtt_port": int(data["aws_mqtt_port"]) if data.get("aws_mqtt_port") else None,
        "aws_endpoint": data.get("aws_endpoint") or None,
    }


@app.post("/api/build")
def build():
    try:
        args = _build_request(request.get_json(force=True) or {})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"job_id": run_build(**args)})


@app.post("/api/prebuild-configurations")
def prebuild_configurations():
    data = request.get_json(force=True) or {}
    sdk_root = data.get("sdk_root") or str(default_sdk_root() or "")
    if not sdk_root:
        return jsonify({"error": "sdk_root is required"}), 400
    try:
        return jsonify(apply_prebuild_configurations(sdk_root, data.get("app_id") or None))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/build-flash")
def build_flash():
    data = request.get_json(force=True) or {}
    try:
        args = _build_request(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    job_id = run_build(
        **args,
        flash_after=True,
        adapter_serial=data.get("adapter_serial"),
        artifact_path=data.get("artifact_path"),
    )
    return jsonify({"job_id": job_id})


@app.get("/api/build")
def builds():
    return jsonify({"jobs": list_jobs()})


@app.get("/api/build/<job_id>")
def build_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job.to_dict())


@app.post("/api/flash")
def flash():
    data = request.get_json(force=True)
    job_id = data.get("job_id")
    if not job_id:
        return jsonify({"error": "job_id required"}), 400
    try:
        result = flash_build(
            job_id,
            adapter_serial=data.get("adapter_serial"),
            artifact_path=data.get("artifact_path"),
            auto_recover=bool(data.get("auto_recover")),
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def main():
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    tools = tool_status(refresh=True)
    sdk_root = default_sdk_root()
    ble_root = default_ble_root()

    print("WiseConnect Build Studio")
    print(f"  Platform     : {tools.get('platform')}")
    print(f"  Workspace    : {WORKSPACE}")
    print(f"  SDK root     : {sdk_root or '(enter path in UI and click Validate & Trust)'}")
    print(f"  BLE examples : {ble_root or 'NOT FOUND until SDK is validated'}")
    print(f"  Tools ready  : {tools.get('ready')} (LLVM: {tools.get('llvm_ready')})")

    if tools.get("missing"):
        print(f"  Missing tools: {', '.join(tools['missing'])}")
        print("    -> install with: slt install pkg.slt")
    if not sdk_root:
        print("  No SDK with WiSeConnect auto-detected.")
        print("    Enter the SDK path in the UI (folder with simplicity_sdk.slcs")
        print("    and extension/wiseconnect/) and click Validate & Trust.")

    print(f"  Open         : http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
