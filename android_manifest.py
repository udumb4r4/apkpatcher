from pathlib import Path
import xml.etree.ElementTree as ET


class AndroidManifest:
    NATIVE_PERMISSION = 'android.app.extractNativeLibs'
    INTERNET_PERMISSION = 'android.permission.INTERNET'

    def __init__(self, manifest_path: Path):
        self.__manifest_path = manifest_path

    def add_internet_permission(self): # TODO: test & refactor
        root = ET.fromstring(self.__get_content())

        internet_perm = None
        for elem in root.iter('uses-permission'):
            if elem.attrib.get('name') == AndroidManifest.INTERNET_PERMISSION:
                internet_perm = elem
                break

        if internet_perm is None:
            internet_perm = ET.Element('uses-permission', {'name': AndroidManifest.INTERNET_PERMISSION})
            root.insert(0, internet_perm)

        self.__set_content(ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8'))

    def allow_native_libs_extraction(self):  # TODO: test & refactor
        root = ET.fromstring(self.__get_content())
        application_elem = root.find('application')

        if application_elem is None:
            application_elem = ET.Element('application')
            root.append(application_elem)

        extract_native_libs_meta = None
        for elem in application_elem.iter('meta-data'):
            if elem.attrib.get('name') == AndroidManifest.NATIVE_PERMISSION:
                extract_native_libs_meta = elem
                break

        if extract_native_libs_meta is None:
            extract_native_libs_meta = ET.Element('meta-data', {'name': AndroidManifest.NATIVE_PERMISSION, 'value': 'true'})
            application_elem.append(extract_native_libs_meta)
        else:
            extract_native_libs_meta.attrib['value'] = 'true'

        self.__set_content(ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8'))

    def find_app_entry_point(self) -> str: # TODO: test & refactor
        tree = ET.parse(self.__get_content())
        root = tree.getroot()

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

    def __set_content(self, xml_content: str):
        with open(self.__manifest_path, 'w') as manifest_file:
            manifest_file.write(xml_content)
