from lxml import etree
from androguard.core.bytecodes.apk import APK

import os
import re
import sys
import zipfile

# importantForAutofill, autofillHints, autofillType
autofill_re = pat = re.compile(b"importantForAutofill|autofill(Hints|Type)")


def analyze_apk(apk_path):
    print("--> {}".format(apk_path))
    apk = APK(apk_path)
    manifest = str(etree.tostring(apk.get_android_manifest_xml(), pretty_print=True, encoding="utf-8"))
    BAS = "BIND_AUTOFILL_SERVICE"
    if BAS in manifest:
        print("[p]", BAS, "permission")

    archive = zipfile.ZipFile(apk_path, 'r')
    for name, type in apk.get_files_types().items():
        if type == "Android binary XML":
            bindata = archive.read(name)
            match = autofill_re.search(bindata)
            if match is not None:
                match_str = match.group().decode("utf-8")
                print("[a]", match_str, 'in "{}"'.format(name))
    print("\n")


def search_autofill_usage(folder):
    for root, dirs, files in os.walk(folder):
        for f in files:
            if f.lower().endswith("apk"):
                analyze_apk(os.path.join(root, f))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("folder as argument")
        sys.exit(-1)
    folder = sys.argv[1]
    if not os.path.isdir(folder):
        print("'{}' doesn't exist or it's a file", folder)
        sys.exit(-1)
    search_autofill_usage(folder)
