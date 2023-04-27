from pathlib import Path
import xml.etree.ElementTree as ET


class AndroidManifestPatcher:
    def __init__(self, manifest_path: Path):
        self.__manifest_path = manifest_path
        self.__android_schema = AndroidManifestPatcher.__find_android_schema(manifest_path)

        ET.register_namespace('android', self.__android_schema)

    def allow_internet_permission(self):
        INTERNET_PERMISSION = 'android.permission.INTERNET'
        root = ET.fromstring(self.__get_content())

        for permission in root.iter('uses-permission'):
            if INTERNET_PERMISSION in permission.attrib.values():
                return

        internet_perm = ET.Element('uses-permission', {f'{{{self.__android_schema}}}name': INTERNET_PERMISSION})
        root.insert(0, internet_perm)

        self.__set_content(ET.tostring(root))

    def allow_native_libs_extraction(self):
        NATIVE_PERMISSION = 'extractNativeLibs'
        root = ET.fromstring(self.__get_content())

        application_elem = root.find('application')

        if not application_elem:
            raise Exception('Manifest got no application tag')

        application_elem.set(f'{{{self.__android_schema}}}{NATIVE_PERMISSION}', 'true')
        self.__set_content(ET.tostring(root))

    def find_app_entry_point(self) -> str: # TODO: test & refactor
        root = ET.fromstring(self.__get_content())

        activity_elem = None
        for elem in root.iter('activity'):
            intent_filter = elem.find('intent-filter')

            if intent_filter is not None:
                action_elem = intent_filter.find('action')
                category_elem = intent_filter.find('category')

                if (not action_elem) or (not category_elem):
                    continue

                if action_elem.attrib.get('name') != 'android.intent.action.MAIN':
                    continue

                if category_elem.attrib.get('name') != 'android.intent.category.LAUNCHER':
                    continue

                activity_elem = elem

        if activity_elem:
            return activity_elem.attrib.get('name')

    def __get_content(self) -> str:
        with open(self.__manifest_path, 'r') as manifest_file:
            return manifest_file.read()

    def __set_content(self, xml_content: bytes):
        with open(self.__manifest_path, 'wb') as manifest_file:
            manifest_file.write(xml_content)

    @staticmethod
    def __find_android_schema(manifest_path: Path) -> str:
        with open(manifest_path, 'r') as manifest_file:
            manifest = ET.parse(manifest_file)

        permission_elem = next(manifest.getroot().iter('uses-permission'))
        return list(permission_elem.attrib.keys())[0].split('{')[1].split('}')[0]
