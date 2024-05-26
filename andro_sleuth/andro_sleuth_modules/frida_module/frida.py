import frida
import json

class FridaScript:
    def __init__(self, process: str) -> None:
        self.__process = frida.get_usb_device().attach(process)
        self.__tracer_classes = list[str]
        self.__tracer_snippets = list[str]
        self.__script = None

    def add_frida_script(self, script: str) -> None:
        with open(script, 'r') as script_file:
            data = json.load(script_file)
        self.__tracer_classes.extend(data['frida_script']['tracer_classes'])
        self.__tracer_snippets.extend(data['frida_script']['tracer_snippets'])

    
    def compile_frida_script(self) -> None:
        script_lines = []
        script_lines.append("Java.perform(function () {")
        
        # Add tracer classes
        for line in self.__tracer_classes:
            script_lines.append(line)
        
        # Add tracer snippets
        for key, snippet in self.__tracer_snippets.items():
            script_lines.append('')
            script_lines.append('// ' + key)
            for line in snippet:
                script_lines.append(line)
        
        script_lines.append('});')
        # Combine lines into a single script
        frida_script_content = '\n'.join(script_lines)
        self.__script = self.__process.create_script(frida_script_content)

    def _load_callback(self, callback_type: str, callback_func: callable):
        self.__script.on(callback_type, callback_func)
        self.__script.load()