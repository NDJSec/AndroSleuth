import inspect

from andro_sleuth.andro_sleuth_core.apk import LoadedAPK
from andro_sleuth.andro_sleuth_modules.crypto_parser_module.crypto_parser import CryptoParser
from andro_sleuth.andro_sleuth_modules.frida_module.frida import FridaScript
from andro_sleuth.andro_sleuth_modules.mallodroid_module.mallodroid import mallodroid


class Modules:
    def __init__(self, frida_scirpt, loadedAPK) -> None:
        self.__frida_script: FridaScript = frida_scirpt
        self.__loadedAPK: LoadedAPK = loadedAPK
        self._loaded_modules: list[any] = list()

    def load_function_table(self) -> dict[str:callable]:
        module_functions = {}
        for name, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if name.startswith("load_"):
                key = name.replace("load_", "")
                module_functions[key] = method
        return module_functions

    def load_frida(self):
        self.__frida_script = FridaScript(self.__loadedAPK.package_name)

    def load_mallodroid(self):
        mallodroid((self.__loadedAPK._a, self.__loadedAPK._dx, self.__loadedAPK._d), frida_script=self.__frida_script)

    def load_crypto(self):
        CryptoParser(self.__frida_script)
