import os
import shutil
import sys
import zipfile
import re

firmware_variants = ["RS916", "RS9116"]


def fix_filename(version):
    for f in os.listdir():
        if os.path.isfile(f) and f.endswith(".rps"):
            for fv in firmware_variants:
                if f.startswith(fv):
                    # fix missing w and make sure that version always matches
                    # W is hardcoded here and works for WiseConnect firmwares with starts with RS91(1)6 only
                    os.rename(f, f"{fv}W{version}.rps")


def normalize_firmware(build_location, rs9116_firmware):
    current_directory = os.getcwd()
    if build_location == "release_packages":
        with zipfile.ZipFile(rs9116_firmware + ".zip", "r") as zf:
            zf.extractall()
            os.chdir(rs9116_firmware)

    version_match = re.search(r'(\.\d+){2,}', rs9116_firmware)
    version = version_match.group() if version_match is not None else "0.0.0.0"

    os.chdir("firmware")
    fix_filename(version)

    for f in os.listdir():
        shutil.copy2(f, os.path.join(current_directory, "..", "manifest"))


if __name__ == "__main__":
    normalize_firmware(sys.argv[1], sys.argv[2])
