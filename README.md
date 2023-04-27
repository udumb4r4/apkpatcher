# apkpatcher
Corss-Platform script used to inject frida scripts and gadget to an APK <br />
This project started as a fork of [apkpatcher](https://github.com/badadaf/apkpatcher) <br />
<br />
*NOTE* that you should use this tool for debugging / educational purposes only!

## Installation
After you made sure that all of the requirements are met, <br />
You may install the package and use the cmdline tool `apkmod`, which comes with the cmdline tool [`buildapp`](https://github.com/mon231/buildapp) <br />

> pip install apkmod

## Patching process
This tool gets an android app installation file (`.apk`) and a [frida js-script](https://frida.re/docs/javascript-api/) <br />
Then builds a new apk with frida-gadget & script runner ready to be installed on non-rooted android devices!

## Requirements
The project assumes that installer already has the following tools in his path:
- android SDK tools (installed from android-sdk online)
  - aapt (default at SDK\build_tools)
  - zipalign (default at SDK\build_tools)
  - apksigner (default at SDK\build_tools)
  - adb (default at SDK\platform_tools, only required if `-i` flag is used)
- apktool [installation manual](https://ibotpeaches.github.io/Apktool/install/)
- keytool (default at jdk or jre bin folders, only required if `-k` flag is missing)
