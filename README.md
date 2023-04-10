# apkpatcher
Corss-Platform script used to inject frida scripts and gadget to an APK <br/>
This project is a fork of original [apkpatcher](https://github.com/badadaf/apkpatcher) <br />
<br />
*NOTE* that you should use this tool for debugging / educational purposes only!

## Installation
WIP (will be a py-pkg)

## Patching process
Just change anything you want, native-elfs in `/lib` folder, [smali-code](https://source.android.com/docs/core/runtime/dalvik-bytecode) from smali folders, manifest file `AndroidManifest.xml`, resources, assets and whatever's out there


And that's it! Now you have a new apk, waiting to be installed it on your android devices!

## Requirements
The project assumes that installer already has the following tools in his path:
- android SDK tools (installed from android-sdk online)
  - aapt (default at SDK\build_tools)
  - zipalign (default at SDK\build_tools)
  - apksigner (default at SDK\build_tools)
  - adb (default at SDK\platform_tools, only required if `-i` flag is used)
- apktool [installation manual](https://ibotpeaches.github.io/Apktool/install/)
- keytool (default at jdk or jre bin folders, only required if `-k` flag is missing)
  ```
  apkpatcher -a base.apk -g ~/Tools/apkpatcher/gadgets/12.5.9/frida-gadget-12.5.9-android-arm.so
  ```
