import argparse
import buildapp
import subprocess
from pathlib import Path
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from frida_gadget_util import FridaGadgetManager
from smali_injector_util import ActivitySmaliInjector
from android_manifest_util import AndroidManifestPatcher


@contextmanager
def decompiled_context(apk_path: Path):
    with TemporaryDirectory() as decompiled_path:
        subprocess.run(
            f'apktool d {apk_path.resolve()} -o {decompiled_path}',
            shell=True,
            check=True,
            input='\n'.encode(),
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL
        )

        yield Path(decompiled_path)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--apk', required=True, help='apk to patch')
    parser.add_argument('-g', '--gadget', required=False, help='frida-gadget file')
    parser.add_argument('-s', '--script', required=True, help='js script to inject')
    parser.add_argument('-o', '--output-file', required=True, help='output patched apk')
    parser.add_argument('-k', '--keystore', required=False, help='path of keystore to use')
    parser.add_argument('-i', '--install', action='store_true', help='adb install after build')
    parser.add_argument('-u', '--update-gadgets', action='store_true', help='download newest gadgets from github')
    parser.add_argument('-w', '--wait-before-repackage', action='store_true', help='Waits for your OK before repackaging the apk')

    return parser.parse_args()


def main():
    args = parse_arguments()

    with decompiled_context(args.apk) as smali_folder:
        gadget = FridaGadgetManager(args.update_gadgets, args.gadget)
        gadget.add_gadget_libs(smali_folder, Path(args.script))

        manifest_path = smali_folder / 'AndroidManifest.xml'
        manifest = AndroidManifestPatcher(manifest_path)

        manifest.allow_internet_permission()
        manifest.allow_native_libs_extraction()

        entry_point = manifest.find_app_entry_point()
        main_activity_injector = ActivitySmaliInjector(smali_folder, entry_point)
        main_activity_injector.inject_to_activity(FridaGadgetManager.INJECTION_SMALI_CODE)

        if args.wait_before_repackage:
            input(f'About to repackage {smali_folder}!\nPress enter to continue...')

        buildapp.build_app(args.output_file, smali_folder, args.keystore_path, args.install_after_build)


if __name__ == '__main__':
    main()
