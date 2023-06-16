# apkpatcher
Corss-Platform tool used to inject frida scripts and gadget to an APK <br />
This project started as a fork of [apkpatcher](https://github.com/badadaf/apkpatcher) <br />
<br />
*NOTE* that you should use this tool for debugging / educational purposes only!

## Installation
The cmdline tool `apkmod`, comes with the tool [`buildapp`](https://github.com/mon231/buildapp) <br />
Install using a pypi package:
> pip install apkmod --upgrade

If you didn't provide the [requirements for buildapp](#Requirements) by yourself, <br />
Use the following command to setup the tool:
> buildapp_fetch_tools

## Patching process
This tool gets an android app installation file (`.apk`) and a [frida js-script](https://frida.re/docs/javascript-api/) <br />
Then builds a new apk with frida-gadget & script runner ready to be installed on non-rooted android devices!

## Requirements
The tool uses [`buildapp`](https://github.com/mon231/buildapp) package, <br />
Therefore you have to provide it's [requirements](https://github.com/mon231/buildapp/#requirements) <br />
Or run the requirements fetcher tool `buildapp_fetch_tools` after the `pip install` command
