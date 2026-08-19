import os
import subprocess
import threading
import time
import wave
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import pythoncom
    import win32com.client
except ImportError:
    pythoncom = None
    win32com = None


# ============================================================
# Configuration
# ============================================================

# This script runs on the Windows host, outside the UTF Docker container.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIO_FILE = os.environ.get(
    "WINDOWS_MEDIA_AUDIO_FILE",
    os.path.join(_SCRIPT_DIR, "test_16k.wav"),
)

# Bind to all host interfaces so the Docker test container can access the
# service using WINDOWS_MEDIA_SERVER_URL=http://<windows-host-ip>:5000.
SERVER_HOST = os.environ.get("WINDOWS_MEDIA_SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("WINDOWS_MEDIA_SERVER_PORT", "5000"))

PLAYER_PROCESS_NAMES = (
    "wmplayer.exe",
    "MediaPlayer.exe",
    "Microsoft.Media.Player.exe",
)

CLASSIC_WMP_PATHS = (
    r"C:\Program Files\Windows Media Player\wmplayer.exe",
    r"C:\Program Files (x86)\Windows Media Player\wmplayer.exe",
)


# ============================================================
# Global state
# ============================================================

player = None
player_process = None
is_playing = False
start_method = None
player_lock = threading.Lock()
stop_event = threading.Event()
loop_thread = None


# ============================================================
# Helpers
# ============================================================

def _ensure_audio_file():
    """Create a 16 kHz tone WAV if the configured file is missing."""
    if os.path.isfile(AUDIO_FILE):
        return AUDIO_FILE

    print(f"[WARN] Audio file not found: {AUDIO_FILE}")
    print("[INFO] Generating a 120-second 16 kHz loop WAV so playback can still start")
    os.makedirs(os.path.dirname(AUDIO_FILE) or ".", exist_ok=True)

    import array
    import math

    rate = 16000
    seconds = 120
    freq = 1000
    amp = 20000
    nframes = rate * seconds
    step = 2 * math.pi * freq / rate
    samples = array.array(
        "h",
        (int(amp * math.sin(index * step)) for index in range(nframes)),
    )
    with wave.open(AUDIO_FILE, "w") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(rate)
        wav_file.writeframes(samples.tobytes())
    print(f"[INFO] Generated {AUDIO_FILE}")
    return AUDIO_FILE


def _audio_duration_sec():
    try:
        with wave.open(AUDIO_FILE, "rb") as wav_file:
            frames = wav_file.getnframes()
            rate = wav_file.getframerate()
            if rate:
                return max(frames / float(rate), 1.0)
    except Exception as e:
        print(f"[WARN] Could not read WAV duration: {e}")
    return 120.0


def _kill_media_players():
    for name in PLAYER_PROCESS_NAMES:
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", name, "/T"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception as e:
            print(f"[WARN] Could not stop {name}: {e}")


def _loop_playlist_path():
    return os.path.join(_SCRIPT_DIR, "hfp_loop.m3u")


def _write_loop_playlist():
    playlist = _loop_playlist_path()
    with open(playlist, "w", encoding="utf-8") as handle:
        handle.write("#EXTM3U\n")
        for _ in range(500):
            handle.write(AUDIO_FILE + "\n")
    return playlist


def _classic_wmplayer():
    for path in CLASSIC_WMP_PATHS:
        if os.path.isfile(path):
            return path
    return None


def _launch_visible_player(target_file):
    """Open the audio in a visible Windows Media Player window."""
    errors = []

    wmplayer = _classic_wmplayer()
    if wmplayer:
        try:
            process = subprocess.Popen(
                [wmplayer, "/play", target_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=False,
            )
            print(f"[INFO] Launched classic Windows Media Player: {wmplayer}")
            return process, f"wmplayer.exe {target_file}"
        except Exception as e:
            errors.append(f"wmplayer.exe: {e}")
            print(f"[WARN] wmplayer.exe launch failed: {e}")

    try:
        os.startfile(target_file)
        print(f"[INFO] Opened default Windows 11 Media Player: {target_file}")
        return None, f"os.startfile {target_file}"
    except Exception as e:
        errors.append(f"os.startfile: {e}")
        print(f"[WARN] os.startfile failed: {e}")

    try:
        process = subprocess.Popen(
            ["cmd", "/c", "start", "", target_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=False,
            shell=False,
        )
        print(f"[INFO] Opened Media Player through start: {target_file}")
        return process, f"start {target_file}"
    except Exception as e:
        errors.append(f"start: {e}")
        print(f"[WARN] start launch failed: {e}")

    raise RuntimeError("; ".join(errors) if errors else "No Media Player launch method succeeded")


def _start_com_loop():
    """Native loop through classic WMP COM. UI switch is optional."""
    global player

    if win32com is None:
        return False, "pywin32 is not installed"

    if pythoncom is not None:
        try:
            pythoncom.CoInitialize()
        except Exception:
            pass

    player = win32com.client.Dispatch("WMPlayer.OCX")
    try:
        player.uiMode = "full"
        player.fullScreen = False
    except Exception as e:
        print(f"[WARN] Could not set Media Player UI mode: {e}")

    try:
        player.playerApplication.switchToPlayerApplication()
        print("[INFO] Media Player UI: VISIBLE")
    except Exception as e:
        print(f"[WARN] switchToPlayerApplication failed, continuing playback: {e}")

    player.settings.autoStart = True
    player.settings.setMode("loop", True)
    player.settings.setMode("shuffle", False)
    player.URL = AUDIO_FILE
    player.controls.play()
    time.sleep(0.5)
    print("[INFO] COM Media Player looping")
    return True, "COM WMPlayer.OCX loop"


def _media_player_running():
    for name in PLAYER_PROCESS_NAMES:
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {name}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if name.lower() in (result.stdout or "").lower():
                return True
        except Exception:
            continue
    return False


def _loop_watchdog():
    """Keep Media Player running until the HFP call ends (/stop)."""
    global player_process

    print("[INFO] Loop watchdog started")
    while not stop_event.wait(2.0):
        with player_lock:
            if not is_playing:
                break
            if player is not None:
                try:
                    state = int(player.playState)
                    if state in (3, 4, 6, 7, 9, 10):
                        continue
                    print(f"[INFO] COM playState={state}; restarting playback")
                    player.controls.play()
                    continue
                except Exception as e:
                    print(f"[WARN] COM playback check failed: {e}")

            if player_process is not None and player_process.poll() is None:
                continue
            if _media_player_running():
                continue

            print("[INFO] Media Player exited; relaunching to keep HFP audio looping")
            try:
                playlist = _write_loop_playlist()
                player_process, method = _launch_visible_player(playlist)
                print(f"[INFO] Restarted with {method}")
            except Exception as e:
                print(f"[ERROR] Loop restart failed: {e}")


# ============================================================
# Start Media Player
# ============================================================

def start_audio():
    global player
    global player_process
    global is_playing
    global start_method
    global loop_thread

    try:
        _ensure_audio_file()
    except Exception as e:
        return False, f"Audio file not found and could not be generated: {e}"

    if not os.path.isfile(AUDIO_FILE):
        return False, f"Audio file not found: {AUDIO_FILE}"

    with player_lock:
        stop_event.set()
        is_playing = False
        old_thread = loop_thread
        loop_thread = None

    if old_thread is not None and old_thread.is_alive():
        old_thread.join(timeout=3)

    with player_lock:
        _kill_media_players()
        player = None
        player_process = None
        start_method = None
        stop_event.clear()

        errors = []
        launched = False

        print("[INFO] Starting Windows Media Player for active HFP call...")
        playlist = _write_loop_playlist()

        # Visible Windows 11 / classic Media Player is required. COM UI
        # switching is unreliable on Windows 11 and previously returned HTTP 400.
        try:
            player_process, method = _launch_visible_player(playlist)
            launched = True
            start_method = method
        except Exception as e:
            errors.append(str(e))
            print(f"[WARN] Visible Media Player launch failed: {e}")

        if not launched:
            try:
                ok, method = _start_com_loop()
                if ok:
                    launched = True
                    start_method = method
            except Exception as e:
                player = None
                errors.append(f"COM: {e}")
                print(f"[WARN] COM Media Player failed: {e}")

        if not launched:
            is_playing = False
            return False, "Failed to start Media Player: " + "; ".join(errors)

        is_playing = True
        loop_thread = threading.Thread(
            target=_loop_watchdog,
            name="hfp-media-loop",
            daemon=True,
        )
        loop_thread.start()

        print("[INFO] Media Player started")
        print(f"[INFO] Playing: {AUDIO_FILE}")
        print("[INFO] Loop: ENABLED until HFP call ends")
        print(f"[INFO] Method: {start_method}")
        return True, f"Audio started and looping ({start_method})"


# ============================================================
# Stop Media Player
# ============================================================

def stop_audio():
    global player
    global player_process
    global is_playing
    global start_method
    global loop_thread

    print("[INFO] Stopping Media Player because HFP call ended...")
    with player_lock:
        stop_event.set()
        is_playing = False
        old_thread = loop_thread
        loop_thread = None
        old_player = player
        player = None
        old_process = player_process
        player_process = None
        start_method = None

    if old_thread is not None and old_thread.is_alive():
        old_thread.join(timeout=3)

    if old_player is not None:
        try:
            old_player.controls.stop()
            old_player.settings.setMode("loop", False)
        except Exception as e:
            print(f"[WARN] COM stop failed: {e}")

    if old_process is not None:
        try:
            old_process.terminate()
        except Exception:
            pass

    _kill_media_players()
    print("[INFO] Media Player stopped")
    return True, "Audio stopped"


# ============================================================
# Status
# ============================================================

def get_status():
    with player_lock:
        if not is_playing:
            return False

        if player is not None:
            try:
                return int(player.playState) == 3
            except Exception:
                pass

        return True


# ============================================================
# HTTP response
# ============================================================

def json_response(handler, status_code, data):
    import json

    response = json.dumps(data).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(response)))
    handler.end_headers()
    handler.wfile.write(response)


# ============================================================
# HTTP server
# ============================================================

class MediaRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/play":
            success, message = start_audio()
            json_response(
                self,
                200 if success else 400,
                {
                    "status": "success" if success else "error",
                    "message": message,
                },
            )
            return

        if self.path == "/stop":
            success, message = stop_audio()
            json_response(
                self,
                200 if success else 400,
                {
                    "status": "success" if success else "error",
                    "message": message,
                },
            )
            return

        if self.path == "/status":
            playing = get_status()
            json_response(
                self,
                200,
                {
                    "playing": playing,
                    "file": AUDIO_FILE,
                },
            )
            return

        json_response(
            self,
            404,
            {
                "status": "error",
                "message": "Unknown command",
            },
        )

    def log_message(self, format, *args):
        print("[HTTP]", format % args)


# ============================================================
# Main
# ============================================================

def main():
    if pythoncom is not None:
        pythoncom.CoInitialize()

    print("=" * 60)
    print("Windows Media Player HFP Audio Server")
    print("=" * 60)
    print(f"Audio file : {AUDIO_FILE}")
    print(f"Server     : http://{SERVER_HOST}:{SERVER_PORT}")
    print()
    print("Commands:")
    print("  GET /play")
    print("  GET /stop")
    print("  GET /status")
    print("=" * 60)

    try:
        _ensure_audio_file()
    except Exception as e:
        print()
        print("[ERROR] Audio file does not exist and could not be generated:")
        print(AUDIO_FILE)
        print(e)
        print()
        return

    server = HTTPServer((SERVER_HOST, SERVER_PORT), MediaRequestHandler)

    print("[INFO] Server is running...")
    print("[INFO] Waiting for commands...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("[INFO] Shutting down...")
        stop_audio()
        server.server_close()
    finally:
        if pythoncom is not None:
            pythoncom.CoUninitialize()


if __name__ == "__main__":
    main()
