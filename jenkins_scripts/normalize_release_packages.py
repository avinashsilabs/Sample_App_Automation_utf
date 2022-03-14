import os
import shutil
import sys
import zipfile

build_location = sys.argv[1]
rs9116_firmware = sys.argv[2]

current_directory = os.getcwd()

if build_location == "build_artifacts":
    if "2.5.0" in rs9116_firmware:
        version_number = int(rs9116_firmware.rsplit(".", 1)[1])
        if 1 <= version_number <= 19:
            package_directory = current_directory + "/firmware"
            os.chdir(package_directory)
            if os.path.exists(package_directory + "/RS916.2.5.0."+str(version_number)+".rps"):
                os.rename("RS916.2.5.0."+str(version_number)+".rps", "RS916W.2.5.0."+str(version_number)+".rps")
            if os.path.exists(package_directory + "/RS9116.2.5.0."+str(version_number)+".rps"):
                os.rename("RS9116.2.5.0."+str(version_number)+".rps", "RS9116W.2.5.0."+str(version_number)+".rps")

    for f in os.listdir("./firmware"):
        if f.startswith("RS91") and f.endswith(".rps"):
            shutil.copy2("./firmware/"+f, "../manifest")
else:
    with zipfile.ZipFile(rs9116_firmware + ".zip", "r") as zf:
        zf.extractall()

    if "2.5.0" in rs9116_firmware:
        version_number = int(rs9116_firmware.rsplit(".", 1)[1])
        if 1 <= version_number <= 19:
            package_directory = current_directory + "/RS916W.2.5.0."+str(version_number)+"/firmware"
            os.chdir(package_directory)
            if os.path.exists(package_directory + "/RS916.2.5.0."+str(version_number)+".rps"):
                os.rename("RS916.2.5.0."+str(version_number)+".rps", "RS916W.2.5.0."+str(version_number)+".rps")
            if os.path.exists(package_directory + "/RS9116.2.5.0."+str(version_number)+".rps"):
                os.rename("RS9116.2.5.0."+str(version_number)+".rps", "RS9116W.2.5.0."+str(version_number)+".rps")

    os.chdir(current_directory)
    for f in os.listdir("./"+rs9116_firmware+"/firmware"):
        if f.startswith("RS91") and f.endswith(".rps"):
            shutil.copy2("./"+rs9116_firmware+"/firmware/"+f, "../manifest")
