import os
import json
import lzma
import time
import shutil
import argparse
import requests
import tempfile
import buildapp
import subprocess
from typing import List
from pathlib import Path
import xml.etree.ElementTree as ET

class Patcher:
    apk_tmp_dir = None
    apk_file_path = None

    ARCH_X86 = 'x86'
    ARCH_X64 = 'x64'
    ARCH_ARM = 'arm'
    ARCH_ARM64 = 'arm64'

    HOOKFILE_NAME = 'libhook.js.so'
    GADGET_FILE_NAME = 'libfrida-gadget.so'
    CONFIG_FILE_NAME = 'libfrida-gadget.config.so'

    INTERNET_PERMISSION = 'android.permission.INTERNET'

    def __init__(self, apk_file_path=None):
        self.apk_file_path = apk_file_path

    @staticmethod
    def print_message(msg):
        print('[*]', msg)

    @staticmethod
    def extract_xz_files(paths: List[Path]):
        for file_path in paths:
            with open(file_path.replace('.xz', ''), 'wb') as extracted_file:
                with lzma.open(file_path) as extracted_buffer:
                    extracted_file.write(extracted_buffer.read())

                file_path.unlink()

    @staticmethod
    def run_command(cmdline):
        pass

    def update_apkpatcher_gadgets(self):
        if not self.has_satisfied_dependencies():
            self.print_warn('One or more dependencies are missing!')
            return False

        frida_version = subprocess.check_output(['frida', '--version']).decode('utf-8').strip()
        self.print_message('Updating frida gadgets according to your frida version: {0}'.format(frida_version))

        github_link = 'https://api.github.com/repos/frida/frida/releases'

        response = requests.get(github_link).text
        releases = json.loads(response)

        release_link = None

        for release in releases:
            if release['tag_name'] == frida_version:
                release_link = release['url']
                break

        response = requests.get(release_link).text
        release_content = json.loads(response)

        assets = release_content['assets']

        list_gadgets = []
        for asset in assets:
            if 'gadget' in asset['name'] and 'android' in asset['name']:
                gadget = dict()
                gadget['name'] = asset['name']
                gadget['url'] = asset['browser_download_url']

                list_gadgets.append(gadget)

        current_folder = os.path.dirname(os.path.abspath(__file__))
        gadgets_folder = os.path.join(current_folder, 'gadgets')
        target_folder = os.path.join(gadgets_folder, frida_version)

        if not os.path.isdir(target_folder):
            os.makedirs(target_folder)

        downloaded_files = []
        for gadget in list_gadgets:
            gadget_file_path = os.path.join(target_folder, gadget['name'])

            if os.path.isfile(gadget_file_path.replace('.xz', '')):
                self.print_message('{0} already exists. Skipping.'.format(gadget['name']))
            else:
                self.download_file(gadget['url'], gadget_file_path)
                downloaded_files.append(gadget_file_path)

        self.print_message('Extracting downloaded files...')

        # TODO: export to func ("unxz_file")
        for downloaded_file in downloaded_files:
            with open(downloaded_file.replace('.xz', ''), 'wb') as extracted_file:
                with lzma.open(downloaded_file) as extracted_buffer:
                    extracted_file.write(extracted_buffer.read())

        self.print_message('Done! Gadgets were updated')
        return True

    def download_file(self, url, target_path):
        file_name = target_path.split('/')[-1]
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')
        total_length = int(total_length)

        with open(target_path, 'wb') as f:
            downloaded = 0

            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    downloaded += len(chunk)
                    f.write(chunk)

    def get_recommended_gadget(self):
        ret = None

        self.print_message('Trying to identify the right frida-gadget...')
        self.print_message('Waiting for device...')
        os.system('adb wait-for-device')
        abi = subprocess.check_output(['adb', 'shell', 'getprop ro.product.cpu.abi']).decode('utf-8').strip()

        self.print_message('The abi is {0}'.format(abi))

        current_folder = os.path.dirname(os.path.abspath(__file__))
        gadgets_folder = os.path.join(current_folder, 'gadgets')
        target_folder = os.path.join(gadgets_folder, frida_version)

        if os.path.isdir(target_folder):
            dir_list = os.listdir(target_folder)
            gadget_files = [f for f in dir_list if os.path.isfile(os.path.join(target_folder, f))]
        else:
            self.print_warn('Gadget folder was not found')
            return ret

        if abi in ['armeabi', 'armeabi-v7a']:
            for gadget_file in gadget_files:
                if 'arm' in gadget_file and '64' not in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        elif abi == 'arm64-v8a' or 'arm64' in abi:
            for gadget_file in gadget_files:
                if 'arm64' in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        elif abi == 'x86':
            for gadget_file in gadget_files:
                if 'i386' in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        elif abi == 'x86_64':
            for gadget_file in gadget_files:
                if 'x86_64' in gadget_file:
                    full_path = os.path.join(target_folder, gadget_file)
                    ret = full_path
                    break

        if ret is None:
            self.print_warn('No recommended gadget file was found.')
        else:
            self.print_message('Architecture identified ({0}). Gadget was selected.' .format(abi))

        return ret

    def extract_apk(self, apk_path, destination_path):
        self.print_message(f'Extracting {apk_path} to {destination_path}')
        subprocess.check_output(['apktool', '-f', 'd', '-o', destination_path, apk_path])

    def has_permission(self, apk_path, permission_name):
        permissions = subprocess.check_output(['aapt', 'dump', 'permissions', apk_path]).decode('utf-8')

        if permission_name in permissions:
            self.print_message('The app {0} has the permission "{1}"'.format(apk_path, permission_name))
            return True
        else:
            self.print_message("The app {0} doesn't have the permission '{1}'".format(apk_path, permission_name))
            return False

    def get_entrypoint_class_name(self, apk_path):
        dump_lines = subprocess.check_output(['aapt', 'dump', 'badging', apk_path]).decode('utf-8').split('\n')

        for line in dump_lines:
            if 'launchable-activity:' in line:
                name_start = line.find('name=')

                return (
                    line[name_start:]
                    .split(' ')[0]
                    .replace('name=', '')
                    .replace('\'', '')
                    .replace('"', '')
                )

        self.print_warn('Something was wrong while getting launchable-activity')

    def get_entrypoint_smali_path(self, base_path, entrypoint_class):
        files_at_path = os.listdir(base_path)
        entrypoint_final_path = None

        for file in files_at_path:
            if file.startswith('smali'):
                entrypoint_tmp = os.path.join(base_path, file, entrypoint_class.replace('.', '/') + '.smali')

                if os.path.isfile(entrypoint_tmp):
                    entrypoint_final_path = entrypoint_tmp
                    break

        if entrypoint_final_path is None:
            self.print_warn('Couldn\'t find the application entrypoint')
        else:
            self.print_message('Found application entrypoint at {0}'.format(entrypoint_final_path))

        return entrypoint_final_path

    def create_temp_folder_for_apk(self, apk_path):
        system_tmp_dir = tempfile.gettempdir()
        apkpatcher_tmp_dir = os.path.join(system_tmp_dir, 'apkptmp')

        apk_name = apk_path.split('/')[-1]

        final_tmp_dir = os.path.join(apkpatcher_tmp_dir, apk_name.replace('.apk', '').replace('.', '_'))

        if os.path.isdir(final_tmp_dir):
            self.print_message('App temp dir already exists. Removing it...')
            shutil.rmtree(final_tmp_dir)

        os.makedirs(final_tmp_dir)

        return final_tmp_dir

    def insert_frida_loader(self, entrypoint_smali_path):
        load_library_injection_code = \
'''
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
'''

        main_activity_loader = \
'''
.method static constructor <clinit>()V
    .locals 1
    .prologue''' + load_library_injection_code +'''
    return-void
.end method
'''

        with open(entrypoint_smali_path, 'r') as smali_file:
            content = smali_file.read()

            if 'frida-gadget' in content:
                self.print_message('The frida-gadget is already in the entrypoint. Skipping...')
                return False

            direct_methods_start_index = content.find('# direct methods')
            direct_methods_end_index = content.find('# virtual methods')

            if direct_methods_start_index == -1 or direct_methods_end_index == -1:
                self.print_warn('Could not find direct methods.')
                return False

            class_constructor_start_index = content.find('.method static constructor <clinit>()V',
                                                         direct_methods_start_index, direct_methods_end_index)

            if class_constructor_start_index == -1:
                has_class_constructor = False
            else:
                has_class_constructor = True

            class_constructor_end_index = -1
            if has_class_constructor:
                class_constructor_end_index = content.find('.end method',
                                                           class_constructor_start_index, direct_methods_end_index)

            if has_class_constructor and class_constructor_end_index == -1:
                self.print_warn('Could not find the end of class constructor.')
                return False

            prologue_start_index = -1
            if has_class_constructor:
                prologue_start_index = content.find('.prologue',
                                                    class_constructor_start_index, class_constructor_end_index)

            no_prologue_case = False
            locals_start_index = -1
            if has_class_constructor and prologue_start_index == -1:
                no_prologue_case = True

                locals_start_index = content.find('.locals ',
                                                  class_constructor_start_index, class_constructor_end_index)

            if no_prologue_case and locals_start_index == -1:
                self.print_warn('Has class constructor. No prologue case, but no "locals 0" found.')
                return False

            locals_end_index = -1
            if no_prologue_case:
                locals_end_index = locals_start_index + len('locals X')

            prologue_end_index = -1
            if has_class_constructor and prologue_start_index > -1:
                prologue_end_index = prologue_start_index + len('.prologue') + 1

            if has_class_constructor:
                if no_prologue_case:
                    new_content = content[0:locals_end_index]

                    if content[locals_end_index] == '0':
                        new_content += '1'
                    else:
                        new_content += content[locals_end_index]

                    new_content += '\n\n    .prologue'
                    new_content += load_library_injection_code
                    new_content += content[locals_end_index+1:]
                else:
                    new_content = content[0:prologue_end_index]
                    new_content += load_library_injection_code
                    new_content += content[prologue_end_index:]
            else:
                tmp_index = direct_methods_start_index + len('# direct methods') + 1
                new_content = content[0:tmp_index]
                new_content += main_activity_loader
                new_content += content[tmp_index:]

        with open(entrypoint_smali_path, 'w') as smali_file:
            smali_file.write(new_content)

        self.print_message('Frida loader was injected in the entrypoint smali file!')
        return True

    def get_arch_by_gadget(self, gadget_path):
        if 'arm' in gadget_path and '64' not in gadget_path:
            return self.ARCH_ARM

        elif 'arm64' in gadget_path:
            return self.ARCH_ARM64

        elif 'i386' in gadget_path or ('x86' in gadget_path and '64' not in gadget_path):
            return self.ARCH_X86

        elif 'x86_64' in gadget_path:
            return self.ARCH_X64

        else:
            return None

    def create_lib_arch_folders(self, base_path, arch):
        sub_dir = None
        sub_dir_2 = None

        libs_path = Path(base_path) / 'lib'
        libs_path.mkdir(exist_ok=True)

        if arch == self.ARCH_ARM:
            sub_dir = libs_path / 'armeabi'
            sub_dir_2 = libs_path / 'armeabi-v7a'
        elif arch == self.ARCH_ARM64:
            sub_dir = libs_path /'arm64-v8a'
        elif arch == self.ARCH_X86:
            sub_dir = libs_path / 'x86'
        elif arch == self.ARCH_X64:
            sub_dir = libs_path / 'x86_64'
        else:
            self.print_warn("Couldn't create the appropriate folder with the given arch.")
            return []

        sub_dir.mkdir(exist_ok=True)

        if arch == self.ARCH_ARM:
            sub_dir_2.mkdir(exist_ok=True)

        if arch == self.ARCH_ARM:
            return [sub_dir, sub_dir_2]
        else:
            return [sub_dir]

    def delete_existing_gadget(self, arch_folder, delete_custom_files=0):
        gadget_path = os.path.join(arch_folder, self.GADGET_FILE_NAME)

        if os.path.isfile(gadget_path):
            os.remove(gadget_path)

        if delete_custom_files & self.CONFIG_BIT:
            config_file_path = os.path.join(arch_folder, self.CONFIG_FILE_NAME)

            if os.path.isfile(config_file_path):
                os.remove(config_file_path)

        if delete_custom_files & self.AUTOLOAD_BIT:
            hookfile_path = os.path.join(arch_folder, self.HOOKFILE_NAME)

            if os.path.isfile(hookfile_path):
                os.remove(hookfile_path)

    def insert_frida_lib(self, base_path, gadget_path, config_file_path=None, auto_load_script_path=None):
        arch = self.get_arch_by_gadget(gadget_path)
        arch_folders = self.create_lib_arch_folders(base_path, arch)

        if not arch_folders:
            self.print_warn('Some error occurred while creating the libs folders')
            return False

        for folder in arch_folders:
            if config_file_path and auto_load_script_path:
                self.delete_existing_gadget(folder, delete_custom_files=self.CONFIG_BIT | self.AUTOLOAD_BIT)

            elif config_file_path and not auto_load_script_path:
                self.delete_existing_gadget(folder, delete_custom_files=self.CONFIG_BIT)

            elif auto_load_script_path and not config_file_path:
                self.delete_existing_gadget(folder, delete_custom_files=self.AUTOLOAD_BIT)

            else:
                self.delete_existing_gadget(folder, delete_custom_files=0)

            target_gadget_path = os.path.join(folder, self.GADGET_FILE_NAME)

            self.print_message('Copying gadget to {0}'.format(target_gadget_path))

            shutil.copyfile(gadget_path, target_gadget_path)

            if config_file_path:
                target_config_path = target_gadget_path.replace('.so', '.config.so')

                self.print_message('Copying config file to {0}'.format(target_config_path))
                shutil.copyfile(config_file_path, target_config_path)

            if auto_load_script_path:
                target_autoload_path = target_gadget_path.replace(self.GADGET_FILE_NAME, self.HOOKFILE_NAME)

                self.print_message('Copying auto load script file to {0}'.format(target_autoload_path))
                shutil.copyfile(auto_load_script_path, target_autoload_path)

        return True

    def repackage_apk(self, base_apk_path, apk_name, target_file=None):
        if target_file is None:
            current_path = os.getcwd()
            target_file = os.path.join(current_path, apk_name.replace('.apk', '_patched.apk'))

            if os.path.isfile(target_file):
                timestamp = str(time.time()).replace('.', '')
                new_file_name = target_file.replace('.apk', '_{0}.apk'.format(timestamp))
                target_file = new_file_name

        self.print_message(f'Repackaging apk to {target_file}')
        subprocess.check_output(['apktool', 'b', base_apk_path, '-o', target_file])
        return target_file

    def create_security_config_xml(self, base_path):
        res_path = os.path.join(base_path, 'res')

        if not os.path.isdir(res_path):
            self.print_message('Resources path not found. Creating one...')
            os.makedirs(res_path)

        xml_path = os.path.join(res_path, 'xml')

        if not os.path.isdir(xml_path):
            self.print_message('res/xml path not found. Creating one...')

            os.makedirs(xml_path)

        netsec_path = os.path.join(xml_path, 'network_security_config.xml')

        if os.path.isfile(netsec_path):
            os.remove(netsec_path)

        with open(netsec_path, 'w') as netsec_file:
            SECURITY_CONTENT = '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="system" /><certificates src="user" /></trust-anchors></base-config></network-security-config>'
            netsec_file.write(SECURITY_CONTENT)

        self.print_message('The network_security_config.xml file was created!')

    def inject_user_certificates_label(self, base_dir):
        self.print_message('Injecting Network Security label to accept user certificates...')

        manifest_path = os.path.join(base_dir, 'AndroidManifest.xml')

        if not os.path.isfile(manifest_path):
            self.print_warn("Couldn't find the Manifest file. Something is wrong with the apk!")

            return False

        with open(manifest_path, 'r') as manifest_file:
            manifest_content = manifest_file.read()

            start_application_tag = manifest_content.find('<application ')
            end_application_tag = manifest_content.find('>', start_application_tag)

        new_manifest = manifest_content[:end_application_tag]
        new_manifest += ' android:networkSecurityConfig="@xml/network_security_config"'
        new_manifest += manifest_content[end_application_tag:]

        with open(manifest_path, 'w') as manifest_file:
            manifest_file.write(new_manifest)

        self.print_message('The Network Security label was added!')

    def has_user_certificates_label(self, base_path):
        manifest_path = os.path.join(base_path, 'AndroidManifest.xml')

        if not os.path.isfile(manifest_path):
            self.print_warn("Couldn't find the Manifest file. Something is wrong with the apk!")

            return False

        with open(manifest_path, 'r') as manifest_file:
            manifest_content = manifest_file.read()

            has_netsec_label = manifest_content.find('network_security_config') != -1

        return has_netsec_label

    def enable_user_certificates(self, base_path):
        if not self.has_user_certificates_label(base_path):
            self.inject_user_certificates_label(base_path)

        self.create_security_config_xml(base_path)

    def inject_permission_manifest(self, base_dir, permission):
        self.print_message('Injecting permission {0} in Manifest...'.format(permission))

        permission_tag = '<uses-permission android:name="{0}"/>'.format(permission)
        manifest_path = os.path.join(base_dir, 'AndroidManifest.xml')

        if not os.path.isfile(manifest_path):
            self.print_warn("Couldn't find the Manifest file. Something is wrong with the apk!")
            return False

        f = open(manifest_path, 'r')
        manifest_content = f.read()
        f.close()

        start_manifest_tag = manifest_content.find('<manifest ')

        if start_manifest_tag == -1:
            self.print_warn('Something wrong with Manifest file')

            return False

        end_manifest_tag = manifest_content.find('>', start_manifest_tag)

        if end_manifest_tag == -1:
            self.print_warn('Something wrong with Manifest file')

            return False

        new_manifest = manifest_content[:end_manifest_tag + 1] + '\n'
        new_manifest += '    '  # indent
        new_manifest += permission_tag
        new_manifest += manifest_content[end_manifest_tag + 1:]

        f = open(manifest_path, 'w')
        f.write(new_manifest)
        f.close()

    def sign_and_zipalign(self, apk_path, keep_keystore):
        if not os.path.isfile("apkpatcherkeystore"):
            self.print_message('Generating a random key...')
            subprocess.call(
                'keytool -genkey -keyalg RSA -keysize 2048 -validity 700 -noprompt -alias apkpatcheralias1 -dname '
                '"CN=apk.patcher.com, OU=ID, O=APK, L=Patcher, S=Patch, C=BR" -keystore apkpatcherkeystore '
                '-storepass password -keypass password 2> /dev/null',
                shell=True)

        self.print_message('Signing the patched apk...')
        subprocess.call(
            'jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore apkpatcherkeystore '
            '-storepass password {0} apkpatcheralias1 >/dev/null 2>&1'.format(apk_path),
            shell=True)

        if not keep_keystore:
            os.remove('apkpatcherkeystore')

        self.print_message('The apk was signed!')
        self.print_message('Optimizing with zipalign...')

        tmp_target_file = apk_path.replace('.apk', '_tmp.apk')
        shutil.move(apk_path, tmp_target_file)

        subprocess.call('zipalign 4 {0} {1}'.format(tmp_target_file, apk_path), stderr=subprocess.STDOUT, shell=True)

        os.remove(tmp_target_file)

        self.print_message('The file was optimized!')

    @staticmethod
    def get_int_frida_version(str_version):
        version_split = str_version.split('.')

        if len(version_split) > 3:
            version_split = version_split[0:3]

        while len(version_split) < 3:
            version_split.append('0')

        return int(''.join(["{num:03d}".format(num=int(i)) for i in version_split]))

    def min_frida_version(self, min_version):
        frida_version = subprocess.check_output(['frida', '--version']).strip().decode('utf-8')

        if self.get_int_frida_version(frida_version) < self.get_int_frida_version(min_version):
            return False

        return True

    @staticmethod
    def get_default_config_file():
        config = '''
{
    "interaction": {
        "type": "script",
        "address": "127.0.0.1",
        "port": 27042,
        "path": "./libhook.js.so"
    }
}
        '''

        path = os.path.join(os.getcwd(), 'generatedConfigFile.config')
        f = open(path, 'w')

        f.write(config)
        f.close()

        return path


def main():
    patcher = Patcher()

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--apk', required=True, help='apk to patch')
    parser.add_argument('-g', '--gadget', required=False, help='frida-gadget file')
    parser.add_argument('-o', '--output-file', required=True, help='output patched apk')
    parser.add_argument('-s', '--script-path', required=True, help='js script to inject')
    parser.add_argument('-i', '--install', help='install after build', action='store_true')
    parser.add_argument('-k', '--keystore-path', help='path of keystore to use', action='store_true')
    parser.add_argument('-e', '--enable-user-certificates', help='add  in apk to accept user certificates', action='store_true')
    parser.add_argument('-w', '--wait-before-repackage', help='Waits for your OK before repackaging the apk', action='store_true')

    args = parser.parse_args()

    if args.verbosity:
        patcher.set_verbosity(int(args.verbosity))
    else:
        patcher.set_verbosity(patcher.VERBOSITY_HIGH)

    if args.update_gadgets:
        patcher.update_apkpatcher_gadgets()

        return 0

    if not os.path.isfile(args.apk):
        raise RuntimeError("The file {0} couldn't be found!".format(args.apk))

    if not patcher.has_satisfied_dependencies('all'):
        raise RuntimeError('One or more dependencies were not satisfied.')

    gadget_to_use = None
    if not args.prevent_frida_gadget:
        if args.gadget:
            gadget_to_use = args.gadget

        else:
            gadget_to_use = patcher.get_recommended_gadget()

        if gadget_to_use is None or not os.path.isfile(gadget_to_use):
            patcher.print_warn('Could not identify the gadget!')

            return 1

    # THE APK PATCHING STARTS HERE

    apk_file_path = args.apk
    temporary_path = patcher.create_temp_folder_for_apk(apk_file_path)

    has_internet_permission = False
    if not args.prevent_frida_gadget:
        has_internet_permission = patcher.has_permission(apk_file_path, patcher.INTERNET_PERMISSION)

    patcher.extract_apk(apk_file_path, temporary_path)

    if not args.prevent_frida_gadget and not has_internet_permission:
        patcher.inject_permission_manifest(temporary_path, patcher.INTERNET_PERMISSION)

    if args.enable_user_certificates:
        patcher.enable_user_certificates(temporary_path)

    if not args.prevent_frida_gadget:
        # START --[ INJECTING FRIDA LIB FILE AND SMALI CODE ]--
        entrypoint_class = patcher.get_entrypoint_class_name(apk_file_path)
        entrypoint_smali_path = patcher.get_entrypoint_smali_path(temporary_path, entrypoint_class)

        patcher.insert_frida_loader(entrypoint_smali_path)

        if args.autoload_script:
            if not patcher.min_frida_version('10.6.33'):
                patcher.print_warn('Autoload is not supported in this version of frida. Update it!')

                return 1

            script_file = args.autoload_script

            if not os.path.isfile(script_file):
                patcher.print_warn('The script {0} was not found.'.format(script_file))

                return 1

            default_config_file = patcher.get_default_config_file()
            patcher.insert_frida_lib(temporary_path, gadget_to_use,
                                     config_file_path=default_config_file, auto_load_script_path=script_file)

        else:
            patcher.insert_frida_lib(temporary_path, gadget_to_use)
        # END --[ INJECTING FRIDA LIB FILE AND SMALI CODE ]--

    apk_file_name = apk_file_path.split('/')[-1]

    if args.wait_before_repackage:
        patcher.print_message('Apkpatcher is waiting for your OK to repackage the apk...')

        answer = input(BColors.COLOR_BLUE + '[*] Are you ready? (y/N): ' + BColors.ENDC)

        while answer.lower() != 'y':
            answer = input(BColors.COLOR_BLUE + '[*] Are you ready? (y/N): ' + BColors.ENDC)

    buildapp.build_app(args.output_file, temporary_path, args.keystore_path, args.install)
    patcher.print_done('The temporary folder was not deleted. Find it at {0}'.format(temporary_path))


if __name__ == '__main__':
    main()
