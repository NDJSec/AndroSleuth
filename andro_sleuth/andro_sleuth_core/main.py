import argparse
import sys
from androguard.core.analysis.analysis import Analysis
from androguard.core import apk, dex
from androguard.decompiler import decompiler
from androguard.misc import AnalyzeAPK
from andro_sleuth_modules.package_parse_module.package_parser import get_packages
from andro_sleuth_modules.crypto_parser_module.crypto_parser import CryptoPaser
from andro_sleuth_modules.frida_module.frida import FridaScript

from loguru import logger

logger.remove()

def _parseargs():
    parser = argparse.ArgumentParser(description="Analyse Android Apps for broken SSL certificate validation.")
    parser.add_argument("-f", "--file", help="APK File to check", type=str, required=True)
    parser.add_argument("-j", "--java", help="Show Java code for results for non-XML output", action="store_true", required=False)
    parser.add_argument("-x", "--xml", help="Print XML output", action="store_true", required=False)	
    parser.add_argument("-d", "--dir", help="Store decompiled App's Java code for further analysis in dir", type=str, required=False)
    args = parser.parse_args()

    return args

def main():

    _args = _parseargs()

    _a = apk.APK(_args.file, raw=False)
    _dx = Analysis()
    for dex_bytes in _a.get_all_dex():
        df = dex.DEX(dex_bytes, using_api=_a.get_target_sdk_version())
        _dx.add(df)
        df.set_decompiler(decompiler.DecompilerDAD(df, _dx))

    _dx.create_xref()
    _d = _dx.vms

    print(f"Analyse file: {_args.file}")
    print(f"Package name: {_a.get_package()}")

    packages = get_packages(_dx)
    frida_script = FridaScript()
    CryptoPaser(frida_script)



if __name__ == "__main__":
    main()