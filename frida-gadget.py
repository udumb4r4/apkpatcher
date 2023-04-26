import requests
from pathlib import Path
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

    def write_into_libs(self, decompiled_folder: Path, js_script: Path, configuration: str):
        # TODO: write into decompiled_folder/lib/<arch>
        pass
