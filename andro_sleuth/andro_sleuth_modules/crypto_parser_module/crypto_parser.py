from typing import Union
from andro_sleuth.andro_sleuth_modules.frida_module.frida import FridaScript


class CryptoParser:
    def __init__(self, frida_script: Union[FridaScript, None]) -> None:
        if frida_script:
            self._frida = frida_script
            self._frida.add_frida_script('andro_sleuth/andro_sleuth_modules/crypto_parser_module/frida_scripts/crypto_script.json')
