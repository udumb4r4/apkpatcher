import re
import lzma
import requests
from pathlib import Path
from shutil import copyfile
from os.path import expanduser
from typing import Optional, Iterable


class FridaGadget:
    def __init__(self, update_resources: bool = False, gadget_path: Optional[Path] = None):
        if gadget_path:
            self.__paths = [gadget_path]
            return

        DEFAULT_GADGETS_FOLDER = Path(expanduser('~/.frida-gadgets'))
        DEFAULT_GADGETS_FOLDER.mkdir(parents=True, exist_ok=True)

        if update_resources:
            FridaGadget.__download_latest_gadgets(DEFAULT_GADGETS_FOLDER)

        self.__paths = list(FridaGadget.__discover_folder_gadgets(DEFAULT_GADGETS_FOLDER))

        if not self.__paths:
            FridaGadget.__download_latest_gadgets(DEFAULT_GADGETS_FOLDER)
            self.__paths = list(FridaGadget.__discover_folder_gadgets(DEFAULT_GADGETS_FOLDER))

    def add_gadget_libs(self, decompiled_folder: Path, script_path: Path):
        for gadget_path in self.__paths:
            arch_lib_folder = decompiled_folder / 'lib' / FridaGadget.__get_gadget_arch(gadget_path)
            arch_lib_folder.mkdir(parents=True, exist_ok=True)

            FridaGadget.__write_libs(arch_lib_folder, gadget_path, script_path)

    @staticmethod
    def __discover_folder_gadgets(gadgets_folder: Path) -> Iterable[Path]:
        for android_gadget in gadgets_folder.glob('frida-gadget-android-*.so'):
            yield android_gadget

    @staticmethod
    def __download_latest_gadgets(gadgets_folder: Path):
        LATEST_RELEASE_URL = 'https://api.github.com/repos/frida/frida/releases/latest'
        latest_release_assets = requests.get(LATEST_RELEASE_URL).json()['assets']

        for asset in latest_release_assets:
            FRIDA_GADGET_ANDROID_REGEX = re.compile(r'frida-gadget-\d+\.\d+\.\d+-android-.*\.so\.xz')

            if FRIDA_GADGET_ANDROID_REGEX.match(asset['name']):
                compressed_gadget_bytes = requests.get(asset['browser_download_url']).content

                if len(compressed_gadget_bytes) != asset['size']:
                    raise Exception('Error downloaded size doesn\'t match asset size!')

                gadget_file_name = re.sub(r'\d+\.\d+\.\d+-', '', asset['name'])[:-len('.xz')]

                with open(gadgets_folder / gadget_file_name, 'wb') as gadget_file:
                    gadget_file.write(lzma.decompress(compressed_gadget_bytes))

    @staticmethod
    def __get_gadget_arch(gadget_path: Path):
        # TODO:
        return 'asasd'

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
