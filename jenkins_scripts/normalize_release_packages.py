import sys
import subprocess
import os
import shutil
import zipfile

build_location = sys.argv[1]
rs9116_firmware = sys.argv[2]

if build_location == "build_artifacts":
    pathdir = "../manifest"
    for f in os.listdir(pathdir):
        print("--------Line 13------------")
        print(f)
        print("--------Line 15------------")
        if f.startswith("rs9116") and f.endswith(".rps"):
            print("File exists")
            os.remove(f)

    for f in os.listdir("./firmware"):
        print("--------Line 21------------")
        print(f)
        print("--------Line 23------------")
        if f.startswith("RS9116") and f.endswith(".rps"):
            print("Copied")
            shutil.copy2(f, "../manifest/"+rs9116_firmware+".rps")
else:
    with zipfile.ZipFile(rs9116_firmware + ".zip", "r") as zf:
        zf.extractall()

    current_directory = os.getcwd()
    if "2.5.0" in rs9116_firmware:
        print("Firmware contains 2.5.0")
        version_number = int(rs9116_firmware.rsplit(".", 1))
        print("----------Line 35--------------")
        print(version_number)
        print("----------Line 37--------------")
        if 1 <= version_number <= 19:
            package_directory = current_directory + "/RS916W.2.5.0."+str(version_number)+"/firmware"
            os.chdir(package_directory)
            if os.path.exists(package_directory + "/RS916.2.5.0."+str(version_number)+".rps"):
                os.rename("RS916.2.5.0."+str(version_number)+".rps", "RS916W.2.5.0."+str(version_number)+".rps")
            if os.path.exists(package_directory + "/RS9116.2.5.0."+str(version_number)+".rps"):
                os.rename("RS9116.2.5.0."+str(version_number)+".rps", "RS9116W.2.5.0."+str(version_number)+".rps")
            dir_list = os.listdir(".")
            print("----------Line 46------------")
            print(dir_list)
            print("----------Line 48------------")

    os.chdir(current_directory)
    for f in os.listdir("./firmware"):
        print("------------Line 52--------------")
        print(f)
        print("------------Line 54--------------")
        if f.startswith("RS9116") and f.endswith(".rps"):
            shutil.copy2(f, "../manifest")
