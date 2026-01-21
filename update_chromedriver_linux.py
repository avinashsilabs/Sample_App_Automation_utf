import os
import requests
import zipfile
import shutil
import subprocess
import platform

CHROMEDRIVER_DIR = os.path.expanduser("~/chromedriver")
CHROMEDRIVER_PATH = os.path.join(CHROMEDRIVER_DIR, "chromedriver")


def get_chrome_version():
    """Get installed Chrome version on Linux."""
    chrome_commands = [
        "google-chrome --version",
        "google-chrome-stable --version",
        "chromium --version",
        "chromium-browser --version",
    ]

    for cmd in chrome_commands:
        try:
            output = subprocess.check_output(
                cmd.split(), universal_newlines=True, stderr=subprocess.DEVNULL
            )
            # Extract version number
            parts = output.strip().split()
            for part in parts:
                if part[0].isdigit():
                    return part
        except Exception:
            continue

    return None


def download_chromedriver():
    """Download and install the latest stable ChromeDriver for Linux."""
    print("Fetching latest ChromeDriver version...")

    try:
        # Get latest stable version info
        url = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
        response = requests.get(url)
        data = response.json()

        stable = data["channels"]["Stable"]
        version = stable["version"]

        # Find linux64 download URL
        linux64_url = None
        for entry in stable["downloads"]["chromedriver"]:
            if entry["platform"] == "linux64":
                linux64_url = entry["url"]
                break

        if not linux64_url:
            print("Could not find linux64 ChromeDriver download URL.")
            return False

        print(f"Downloading ChromeDriver version {version}...")

        # Download and extract
        zip_path = "chromedriver_temp.zip"
        response = requests.get(linux64_url, stream=True)
        with open(zip_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        # Extract chromedriver
        os.makedirs(CHROMEDRIVER_DIR, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for member in zip_ref.namelist():
                if member.endswith("chromedriver") and not member.endswith("/"):
                    zip_ref.extract(member, CHROMEDRIVER_DIR)
                    extracted = os.path.join(CHROMEDRIVER_DIR, member)
                    shutil.move(extracted, CHROMEDRIVER_PATH)
                    # Make executable
                    os.chmod(CHROMEDRIVER_PATH, 0o755)
                    # Clean up empty subdirectory
                    subdir = os.path.dirname(extracted)
                    if subdir != CHROMEDRIVER_DIR and os.path.exists(subdir):
                        shutil.rmtree(subdir)
                    break

        os.remove(zip_path)
        print()
        print("=" * 70)
        print(f"SUCCESS! ChromeDriver {version} installed successfully!")
        print("=" * 70)
        print(f"Installation location: {CHROMEDRIVER_PATH}")
        print()
        print("NEXT STEPS TO USE CHROMEDRIVER:")
        print(f"1. Add this path to your PATH: {CHROMEDRIVER_DIR}")
        print("2. Restart your terminal")
        print("3. Verify installation: chromedriver --version")
        print()
        print("To add to PATH:")
        print(f"  echo 'export PATH=\"{CHROMEDRIVER_DIR}:$PATH\"' >> ~/.bashrc")
        print("  source ~/.bashrc")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"Error downloading ChromeDriver: {e}")
        return False


def main():
    print()
    print("=" * 70)
    print("ChromeDriver Update Tool (Linux)")
    print("=" * 70)
    print()

    chrome_version = get_chrome_version()
    if chrome_version:
        print(f"Installed Chrome version: {chrome_version}")
    else:
        print("Chrome version: Not detected")

    # Check current ChromeDriver
    chromedriver_cmd = shutil.which("chromedriver")
    if chromedriver_cmd:
        print(f"Current ChromeDriver in PATH: {chromedriver_cmd}")
        try:
            output = subprocess.check_output(
                [chromedriver_cmd, "--version"], universal_newlines=True
            )
            print(f"Current version: {output.strip()}")
        except:
            pass
    else:
        print("Current ChromeDriver: Not found in PATH")

    print()
    download_chromedriver()


if __name__ == "__main__":
    main()
