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

        internet_perm = ET.Element('uses-permission', {f'{{{self.__android_schema}}}:name': INTERNET_PERMISSION})
        root.insert(0, internet_perm)

        self.__set_content(ET.tostring(root))

    def allow_native_libs_extraction(self):
        root = ET.fromstring(self.__get_content())
        application_elem = root.find('application')

        if not application_elem:
            raise Exception('Manifest got no application tag')

        native_permission = f'{{{self.__android_schema}}}extractNativeLibs'
        application_elem.attrib.pop(native_permission, None)
        application_elem.attrib[native_permission] = 'true'

        self.__set_content(ET.tostring(root))

    def find_app_entry_point(self) -> str:
        root = ET.fromstring(self.__get_content())
        application_elem = root.find('application')

        if not application_elem:
            raise Exception('Manifest got no application tag')

        for activity in application_elem.iter('activity'):
            for intent_filter in activity.iter('intent-filter'):
                action_elem = intent_filter.find('action')
                category_elem = intent_filter.find('category')
                android_name_tag = f'{{{self.__android_schema}}}name'

                if (action_elem is None) or (category_elem is None):
                    continue

                if action_elem.get(android_name_tag) != 'android.intent.action.MAIN':
                    continue

                if category_elem.attrib.get(android_name_tag) != 'android.intent.category.LAUNCHER':
                    continue

                return activity.attrib.get(android_name_tag)

        raise Exception('Couldn\'t find activity with MAIN action for LAUNCHER catagory')

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
