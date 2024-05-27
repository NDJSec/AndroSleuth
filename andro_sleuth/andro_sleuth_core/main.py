import argparse
import sys
from androguard.core.analysis.analysis import Analysis
from androguard.core import apk, dex
from androguard.decompiler import decompiler
from andro_sleuth_modules.package_parse_module.package_parser import get_packages
from andro_sleuth_modules.crypto_parser_module.crypto_parser import CryptoPaser
from andro_sleuth_modules.mallodroid_module import mallodroid
from andro_sleuth_modules.frida_module.frida import FridaScript

from loguru import logger

logger.remove()
logger.level("ARGS INFO", no=22, color="<white>")
logger.add(sys.stdout, level="ARGS INFO")

def _parseargs():
    parser = argparse.ArgumentParser(description="Analyse Android Apps for cryptographic misuse.")
    parser.add_argument("-i", "--input", help="APK File to check", type=str, required=True)
    parser.add_argument("-o", "--output", help="Destination for output file", type=str, required=True)

    module_group = parser.add_argument_group("Modules")
    module_group.add_argument("-a", "--all", help="Run all modules", action="store_true", required=False)
    module_group.add_argument("-m", "--mallodroid", help="Run mallodroid module", action="store_true", required=False)
    module_group.add_argument("-f", "--frida", help="Enable Frida tracing modules", action="store_true", required=False)
    module_group.add_argument("-c", "--crypto", help="Run the Crypto Parser module", action="store_true", required=False)
    args = parser.parse_args()

    return args

def main():

    _args = _parseargs()
    logger.log("ARGS INFO", "AndroSleuth Started")
    logger.log("ARGS INFO", f"APK Loaded: {_args.input}")
    logger.log("ARGS INFO", f"Output location: {_args.output}")

    _a = apk.APK(_args.input, raw=False)
    _dx = Analysis()
    for dex_bytes in _a.get_all_dex():
        df = dex.DEX(dex_bytes, using_api=_a.get_target_sdk_version())
        _dx.add(df)
        df.set_decompiler(decompiler.DecompilerDAD(df, _dx))

    _dx.create_xref()
    _d = _dx.vms
    package_name = _a.get_package()
    frida_script = None

    logger.success(f"Analyse file: {_args.input}")
    logger.success(f"Package name: {package_name}")

    packages = get_packages(_dx, package_name)
    
    if _args.frida:
        frida_script = FridaScript(package_name)
    if _args.mallodroid:
       mallodroid((_a, _dx, _d), frida_script) 
    if _args.crypto:
        CryptoPaser(frida_script)


if __name__ == "__main__":
    main()