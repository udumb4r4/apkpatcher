import os
import json
import lzma
import time
import shutil
import argparse
import requests
import buildapp
import subprocess
from typing import List
from pathlib import Path
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from tempfile import TemporaryDirectory


NATIVE_PERMISSION = 'android.app.extractNativeLibs'
INTERNET_PERMISSION = 'android.permission.INTERNET'


@contextmanager
def decompiled_context(apk_path: Path):
    with TemporaryDirectory() as decompiled_path:
        # TODO: f'apktool d {apk_path.resolve()} -o {decompiled_path}'
        yield Path(decompiled_path)


def add_internet_permission(manifest_xml: str) -> str: # TODO: test & refactor
    root = ET.fromstring(manifest_xml)

    internet_perm = None
    for elem in root.iter('uses-permission'):
        if elem.attrib.get('name') == INTERNET_PERMISSION:
            internet_perm = elem
            break

    if internet_perm is None:
        internet_perm = ET.Element('uses-permission', {'name': INTERNET_PERMISSION})
        root.insert(0, internet_perm)

    return ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8')


def allow_native_libs_extraction(manifest_xml: str) -> str:  # TODO: test & refactor
    root = ET.fromstring(manifest_xml)
    application_elem = root.find('application')

    if application_elem is None:
        application_elem = ET.Element('application')
        root.append(application_elem)

    extract_native_libs_meta = None
    for elem in application_elem.iter('meta-data'):
        if elem.attrib.get('name') == NATIVE_PERMISSION:
            extract_native_libs_meta = elem
            break

    if extract_native_libs_meta is None:
        extract_native_libs_meta = ET.Element('meta-data', {'name': NATIVE_PERMISSION, 'value': 'true'})
        application_elem.append(extract_native_libs_meta)
    else:
        extract_native_libs_meta.attrib['value'] = 'true'

    return ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8')


def find_app_entry_point(manifest_file): # TODO: test & refactor
    tree = ET.parse(manifest_file)
    root = tree.getroot()

    activity_elem = None
    for elem in root.iter('activity'):
        intent_filter = elem.find('intent-filter')
        if intent_filter is not None:
            action_elem = intent_filter.find('action')
            category_elem = intent_filter.find('category')
            if (action_elem is not None and action_elem.attrib.get('name') == 'android.intent.action.MAIN' and
                    category_elem is not None and category_elem.attrib.get('name') == 'android.intent.category.LAUNCHER'):
                activity_elem = elem
                break

    if activity_elem is not None:
        return activity_elem.attrib.get('name')
    else:
        return None


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--apk', required=True, help='apk to patch')
    parser.add_argument('-g', '--gadget', required=False, help='frida-gadget file')
    parser.add_argument('-o', '--output-file', required=True, help='output patched apk')
    parser.add_argument('-s', '--script-path', required=True, help='js script to inject')
    parser.add_argument('-i', '--install', action='store_true', help='adb install after build')
    parser.add_argument('-k', '--keystore-path', required=False, help='path of keystore to use')
    parser.add_argument('-u', '--update-gadgets', action='store_true', help='download newest gadgets from github')
    parser.add_argument('-w', '--wait-before-repackage', action='store_true', help='Waits for your OK before repackaging the apk')

    return parser.parse_args()


def main():
    args = parse_arguments()
    # TODO: apktool d args.apk -o tempfolder
    with decompiled_context(args.apk) as smali_folder:
        manifest_path = smali_folder / 'AndroidManifest.xml'

        with open(manifest_path, 'r') as manifest_file:
            manifest_xml = manifest_file.read()

        manifest_xml = add_internet_permission(manifest_xml) # TODO: manifest inject android.permission.INTERNET if not existing
        manifest_xml = allow_native_libs_extraction(manifest_xml) # TODO: manifest inject extractNative="true"

        with open(manifest_path, 'w') as manifest_file:
            manifest_file.write(manifest_xml)

        # TODO: obtain frida-gadget files (import `frida-gadget`)
        # TODO: create lib/<arch>/ folders with gadget and scripts
        # TODO: app-entry-point inject LoadLibrary

        if args.wait_before_repackage:
            input(f'About to repackage {smali_folder}!\nPress enter to continue...')

        buildapp.build_app(args.output_file, smali_folder, args.keystore_path, args.install_after_build)


if __name__ == '__main__':
    main()
