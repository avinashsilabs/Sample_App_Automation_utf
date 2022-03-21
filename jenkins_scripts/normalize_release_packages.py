import os
import shutil
import sys
import zipfile
import re


def fix_filename(version):
    for filename in os.listdir():
        f = os.path.join("./", filename)
        if os.path.isfile(f) and f.endswith(".rps"):
            if f.startswith("RS916"):
                os.rename(f, f"./RS916W{version}.rps")  # fix missing w and make sure that version always matches
            if f.startswith("RS9116"):
                os.rename(f, f"./RS9116W{version}.rps")  # fix missing w and make sure that version always matches


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
