from andro_sleuth_modules.frida_module.frida import FridaScript

class CryptoPaser:
    def __init__(self, frida_script: FridaScript) -> None:
        self._frida = frida_script
        self._frida.add_frida_script('frida_scripts/crypto_script.json')
