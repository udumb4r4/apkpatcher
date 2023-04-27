import setuptools


setuptools.setup(
    name = "apkmod",
    version = "1.0.0",
    author = "Ariel Tubul",
    description = "Apk frida-gadget injector script",
    packages = setuptools.find_packages(),
    url = "https://github.com/mon231/apkpatcher/",
    install_requires = ['requests', 'buildapp'],
    entry_points = {'console_scripts': ['apkmod=apkmod.main:main']}
)
