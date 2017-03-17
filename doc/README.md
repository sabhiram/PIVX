PIVX Core 2.1.6
=====================

This is the official reference wallet for Dash digital currency and comprises the backbone of the Dash peer-to-peer network. You can [download Dash Core](https://www.dash.org/downloads/) or [build it yourself](#building) using the guides below.

Running
---------------------
The following are some helpful notes on how to run PIVX on your native platform.

### Unix

You need the Qt4 run-time libraries to run PIVX-Qt. On Debian or Ubuntu:

	sudo apt-get install libqtgui4

Unpack the files into a directory and run:

- bin/32/pivx-qt (GUI, 32-bit) or bin/32/pivxd (headless, 32-bit)
- bin/64/pivx-qt (GUI, 64-bit) or bin/64/pivxd (headless, 64-bit)



### Windows

Unpack the files into a directory, and then run pivx-qt.exe.

### OS X

Drag PIVX-Qt to your applications folder, and then run PIVX-Qt.

### Need Help?

* See the documentation at the [PIVX Wiki](https://en.bitcoin.it/wiki/Main_Page) ***TODO***
for help and more information.
* Ask for help on https://bitcointalk.org/index.php?topic=1262920.0
* A new forum will be available soon on pivx-crypto.com

Building
---------------------
The following are developer notes on how to build PIVX on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [OS X Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The Pivx repo's [root README](https://github.com/pivx-crypto/pivx/blob/master/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Multiwallet Qt Development](multiwallet-qt.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- Source Code Documentation ***TODO***
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Unit Tests](unit-tests.md)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)

License
---------------------
Distributed under the [MIT software license](http://www.opensource.org/licenses/mit-license.php).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
