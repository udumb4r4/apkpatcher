import setuptools
from pathlib import Path


REQUIREMENTS_FILE = Path('./requirements.txt')

setuptools.setup(
    name = "apkmod",
    version = "1.0.0",
    author = "Ariel Tubul",
    description = "Apk frida-gadget injector script",
    packages = setuptools.find_packages(),
    url = "https://github.com/mon231/apkpatcher/",
    install_requires = [req for req in REQUIREMENTS_FILE.read_text().splitlines() if req],
    entry_points = {'console_scripts': ['apkmod=apkmod.main:main']}
)
