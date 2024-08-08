from pathlib import Path

from andro_sleuth.andro_sleuth_core.apk import LoadedAPK
from andro_sleuth.andro_sleuth_core.args import InlineArgumentParser
from andro_sleuth.andro_sleuth_core.cli import BaseCli

from androguard.core.analysis.analysis import Analysis
from androguard.core import apk, dex
from androguard.decompiler import decompiler

from loguru import logger

from andro_sleuth.andro_sleuth_modules.modules import Modules
from andro_sleuth.andro_sleuth_modules.package_parse_module.package_parser import get_packages


class AndroSleuth(BaseCli):
    prompt = "(AndroSleuth) > "

    def __init__(self):
        super().__init__()
        self._loadedAPK = LoadedAPK()
        self._loaded_modules: set = set()
        self._frida_script = None
        self.__modules: Modules = None

    def do_loadapk(self, args: str = '') -> None:
        parser = InlineArgumentParser(description="Analyse Android Apps for cryptographic misuse.")

        parser.add_argument("-i", "--input", help="APK File to check", type=str, required=True)
        parser.add_argument("-o", "--output", help="Destination for output file", type=str, required=True)

        args = parser.parse_args_inline(args)
        if not args:
            return

        logger.log("ARGS INFO", f"APK Loaded: {args.input}")
        logger.log("ARGS INFO", f"Output location: {args.output}")

        self._loadedAPK._a = apk.APK(args.input, raw=False)
        self._loadedAPK._dx = Analysis()
        for dex_bytes in self._loadedAPK._a.get_all_dex():
            df = dex.DEX(dex_bytes, using_api=self._loadedAPK._a.get_target_sdk_version())
            self._loadedAPK._dx.add(df)
            df.set_decompiler(decompiler.DecompilerDAD(df, self._loadedAPK._dx))

        self._loadedAPK._dx.create_xref()
        self._loadedAPK._d = self._loadedAPK._dx.vms
        self._loadedAPK.package_name = self._loadedAPK._a.get_package()

        self.__modules = Modules(self._frida_script, self._loadedAPK)

        logger.success(f"Analyse file: {args.input}")
        logger.success(f"Package name: {self._loadedAPK.package_name}")

    def do_loadmodules(self, args: str = '') -> None:
        parser = InlineArgumentParser()
        parser.add_argument("all", nargs="?", help="Run all modules")
        parser.add_argument("frida", nargs="?", help="Enable Frida tracing on supported modules")
        parser.add_argument("mallodroid", nargs="?", help="Run mallodroid module")
        parser.add_argument("crypto", nargs="?", help="Run the Crypto Parser module")
        args = parser.parse_args_inline(args)

        if self.__modules:
            module_functions = self.__modules.load_function_table()
        else:
            print("No APK loaded. See loadapk to load an APK into AndroSleuth")
            return

        if all(not getattr(args, attr) for attr in vars(args)):
            print("No Args")
            return

        if args.all:
            self._loaded_modules = list((module_functions.keys, module_functions.values()))
        else:
            for arg, func in module_functions.items():
                if arg in args:
                    self._loaded_modules.append((arg, func))

        if not self._loaded_modules:
            print("No modules loaded")

    def do_listmodules(self, args) -> None:
        """
        List currently loaded modules.
        """
        if len(self._loaded_modules) == 0:
            print("No Modules Loaded. See loadmodules for more information.")
            return

        for module in self._loaded_modules:
            print(module[0])

    def do_listapk(self, line):
        """
        List the apk currently loaded into AndroSleuth.
        """
        if self._loadedAPK.package_name:
            print(f"Loaded APK: {self._loadedAPK.package_name}")
        else:
            print("No APK loaded. See loadapk to load an APK")

    def do_listdependencies(self, args: str = "") -> None:
        """
        List/Search the found 3rd party dependencies for the loaded APK
        """
        if not self._loadedAPK.package_name:
            print("No APK loaded. See loadapk to load an APK")
            return

        get_packages(self._loadedAPK._dx, self._loadedAPK.package_name)

    def do_execute(self, line) -> None:
        """
        Run the current configuration.
        """
        pass

    def do_exit(self, line) -> bool:
        """
        Exit from program.
        """
        return True
