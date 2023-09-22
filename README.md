# apkpatcher
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fmon231%2Fapkpatcher&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23AC3838&title=hits&edge_flat=false)](https://hits.seeyoufarm.com) <br />
Corss-Platform tool used to inject frida scripts and gadget to an APK <br />
This project started as a fork of [apkpatcher](https://github.com/badadaf/apkpatcher) <br />
<br />
*NOTE* that you should use this tool for debugging / educational purposes only!

## Installation
The cmdline tool `apkmod`, comes with the tool [`buildapp`](https://github.com/mon231/buildapp) <br />
Install using a pypi package, then fetch tools for buildapp:
> pip install apkmod --upgrade && buildapp_fetch_tools

## Automation
You can use `apkmod` in your github workflow process! <br />
Simply add a `build.yml` at your repo `.github/workflows` folder:
```yml
name: build patched app
on: [push]

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: mon231/apkpatcher@master
        with:
          original-apk: 'original.apk'
          output-apk: 'patched.apk'
          frida-script: 'frida.js'
```

## Patching process
This tool gets an android app installation file (`.apk`) and a [frida js-script](https://frida.re/docs/javascript-api/) <br />
Then builds a new apk with frida-gadget & script runner ready to be installed on non-rooted android devices!

## Requirements
The tool uses [`buildapp`](https://github.com/mon231/buildapp) package, <br />
Therefore you have to provide it's [requirements](https://github.com/mon231/buildapp/#requirements) <br />
Or run the requirements fetcher tool `buildapp_fetch_tools` after the `pip install` command
