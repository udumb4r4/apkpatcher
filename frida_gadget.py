import requests
from pathlib import Path
from shutil import copyfile
from typing import Optional

class FridaGadget:
    def __init__(self, update_resources: bool = False, gadget_path: Optional[Path] = None):
        if gadget_path:
            # TODO: store path
            return

        if update_resources:
            # TODO: update gadgets folder (from github, using requests)
            pass

        # TODO: obtain gadget files

    def add_gadget_libs(self, decompiled_folder: Path, script_path: Path):
        # TODO: for each arch: __write_libs
        # TODO: write into decompiled_folder/lib/<arch>
        pass

    @staticmethod
    def __write_libs(arch_lib_folder: Path, gadget_path: Path, script_path: Path):
        SCRIPT_PATH = './libhook.js.so'
        GADGET_PATH = './libfrida-gadget.so'
        CONFIG_PATH = './libfrida-gadget.config.so'
        FRIDA_CONFIGURATIONS = \
f'''
{{
    "interaction": {{
        "type": "script",
        "address": "127.0.0.1",
        "port": 27042,
        "path": "{SCRIPT_PATH}"
    }}
}}
'''
        copyfile(gadget_path, arch_lib_folder / GADGET_PATH)
        copyfile(script_path, arch_lib_folder / SCRIPT_PATH)

        with open(arch_lib_folder / CONFIG_PATH, 'w') as config_file:
            config_file.write(FRIDA_CONFIGURATIONS)
