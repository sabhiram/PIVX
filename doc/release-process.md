Release Process
====================

* update translations (ping wumpus, Diapolo or tcatm on IRC)
* see https://github.com/pivx-project/pivx/blob/master/doc/translation_process.md#syncing-with-transifex

* * *

###First time / New builders
Check out the source code in the following directory hierarchy.

	cd /path/to/your/toplevel/build
	git clone https://github.com/dashpay/gitian.sigs.git
	git clone https://github.com/dashpay/dash-detached-sigs.git
	git clone https://github.com/devrandom/gitian-builder.git
	git clone https://github.com/dashpay/dash.git

###Dash maintainers/release engineers, update (commit) version in sources

	pushd ./dash
	contrib/verifysfbinaries/verify.sh
	configure.ac
	doc/README*
	doc/Doxyfile
	contrib/gitian-descriptors/*.yml
	src/clientversion.h (change CLIENT_VERSION_IS_RELEASE to true)

	# tag version in git

	git tag -s v(new version, e.g. 2.1.3.4)

	# write release notes. git shortlog helps a lot, for example:

	git shortlog --no-merges v(current version, e.g. 2.1.3.0)..v(new version, e.g. 2.1.4.0)

* * *

###Setup and perform Gitian builds

 Setup Gitian descriptors:

###perform gitian builds

 From a directory containing the pivx source, gitian-builder and gitian.sigs

	export SIGNER=(your gitian key)
	export VERSION=(new version, e.g. 2.1.4.0)
	pushd ./pivx
	git checkout v${VERSION}
	popd

  Ensure your gitian.sigs are up-to-date if you wish to gverify your builds against other Gitian signatures.

	pushd ./gitian.sigs
	git pull
	popd

  Ensure gitian-builder is up-to-date to take advantage of new caching features (`e9741525c` or later is recommended).

	pushd ./gitian-builder
	git pull

###Fetch and create inputs: (first time, or when dependency versions change)

	mkdir -p inputs
	wget -P inputs https://bitcoincore.org/cfields/osslsigncode-Backports-to-1.7.1.patch
	wget -P inputs http://downloads.sourceforge.net/project/osslsigncode/osslsigncode/osslsigncode-1.7.1.tar.gz

 Register and download the Apple SDK: see [OS X readme](README_osx.txt) for details.

 Or you can download it from our website;
 
 	http://pivx-crypto.com/files/sdk/MacOSX10.7.sdk.tar.gz
 	
 If you will be building the RPi2 binary as well, you will need this file in 'gitian-builder/inputs' folder
 
 	http://pivx-crypto.com/files/sdk/raspberrypi-tools.tar.gz
 	
###Optional: Seed the Gitian sources cache

 Using a Mac, create a tarball for the 10.9 SDK and copy it to the inputs directory:

	tar -C /Volumes/Xcode/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/ -czf MacOSX10.9.sdk.tar.gz MacOSX10.9.sdk

###Optional: Seed the Gitian sources cache and offline git repositories

By default, Gitian will fetch source files as needed. To cache them ahead of time:

	make -C ../pivx/depends download SOURCES_PATH=`pwd`/cache/common

Only missing files will be fetched, so this is safe to re-run for each build.

###Build PIVX Core for Linux, Windows, and OS X:

	./bin/gbuild --commit pivx=v${VERSION} ../pivx/contrib/gitian-descriptors/gitian-linux.yml
	./bin/gsign --signer $SIGNER --release ${VERSION}-linux --destination ../gitian.sigs/ ../pivx/contrib/gitian-descriptors/gitian-linux.yml
	mv build/out/pivx-*.tar.gz build/out/src/pivx-*.tar.gz ../
	./bin/gbuild --commit pivx=v${VERSION} ../pivx/contrib/gitian-descriptors/gitian-win.yml
	./bin/gsign --signer $SIGNER --release ${VERSION}-win --destination ../gitian.sigs/ ../pivx/contrib/gitian-descriptors/gitian-win.yml
	mv build/out/pivx-*.zip build/out/pivx-*.exe ../
	./bin/gbuild --commit pivx=v${VERSION} ../pivx/contrib/gitian-descriptors/gitian-osx.yml
	./bin/gsign --signer $SIGNER --release ${VERSION}-osx-unsigned --destination ../gitian.sigs/ ../pivx/contrib/gitian-descriptors/gitian-osx.yml
	mv build/out/pivx-*-unsigned.tar.gz inputs/pivx-osx-unsigned.tar.gz
	mv build/out/pivx-*.tar.gz build/out/pivx-*.dmg ../
	popd

  Build output expected:

  1. source tarball (pivx-${VERSION}.tar.gz)
  2. linux 32-bit and 64-bit binaries dist tarballs (pivx-${VERSION}-linux[32|64].tar.gz)
  3. windows 32-bit and 64-bit installers and dist zips (pivx-${VERSION}-win[32|64]-setup.exe, pivx-${VERSION}-win[32|64].zip)
  4. OSX unsigned installer (pivx-${VERSION}-osx-unsigned.dmg)
  5. Gitian signatures (in gitian.sigs/${VERSION}-<linux|win|osx-unsigned>/(your gitian key)/

###Next steps:

Commit your signature to gitian.sigs:

	pushd gitian.sigs
	git add ${VERSION}-linux/${SIGNER}
	git add ${VERSION}-win-unsigned/${SIGNER}
	git add ${VERSION}-osx-unsigned/${SIGNER}
	git commit -a
	git push  # Assuming you can push to the gitian.sigs tree
	popd

  Wait for OSX detached signature:
	Once the OSX build has 3 matching signatures ***TODO*** will sign it with the apple App-Store key.
	He will then upload a detached signature to be combined with the unsigned app to create a signed binary.

  Create (and optionally verify) the signed OS X binary:

	pushd ./gitian-builder
	# Fetch the signature as instructed by Evan
	cp signature.tar.gz inputs/
	./bin/gbuild -i ../pivx/contrib/gitian-descriptors/gitian-osx-signer.yml
	./bin/gsign --signer $SIGNER --release ${VERSION}-osx-signed --destination ../gitian.sigs/ ../pivx/contrib/gitian-descriptors/gitian-osx-signer.yml
	mv build/out/pivx-osx-signed.dmg ../pivx-${VERSION}-osx.dmg
	popd

  Create (and optionally verify) the signed Windows binaries:

	pushd ./gitian-builder
	./bin/gbuild -i --commit signature=v${VERSION} ../dash/contrib/gitian-descriptors/gitian-win-signer.yml
	./bin/gsign --signer $SIGNER --release ${VERSION}-win-signed --destination ../gitian.sigs/ ../dash/contrib/gitian-descriptors/gitian-win-signer.yml
	./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-win-signed ../dash/contrib/gitian-descriptors/gitian-win-signer.yml
	mv build/out/dash-*win64-setup.exe ../dash-${VERSION}-win64-setup.exe
	mv build/out/dash-*win32-setup.exe ../dash-${VERSION}-win32-setup.exe
	popd

Commit your signature for the signed OS X/Windows binaries:

	pushd gitian.sigs
	git add ${VERSION}-osx-signed/${SIGNER}
	git add ${VERSION}-win-signed/${SIGNER}
	git commit -a
	git push  # Assuming you can push to the gitian.sigs tree
	popd

-------------------------------------------------------------------------

### After 3 or more people have gitian-built and their results match:

- Perform code-signing.

    - Code-sign Windows -setup.exe (in a Windows virtual machine using signtool)

- Create `SHA256SUMS.asc` for the builds, and GPG-sign it:
```bash
sha256sum * > SHA256SUMS
gpg --digest-algo sha256 --clearsign SHA256SUMS # outputs SHA256SUMS.asc
rm SHA256SUMS
```
(the digest algorithm is forced to sha256 to avoid confusion of the `Hash:` header that GPG adds with the SHA256 used for the files)
Note: check that SHA256SUMS itself doesn't end up in SHA256SUMS, which is a spurious/nonsensical entry.

- Upload zips and installers, as well as `SHA256SUMS.asc` from last step, to the bitcoin.org server
  into `/var/www/bin/bitcoin-core-${VERSION}`

- Add release notes for the new version to the directory `doc/release-notes` in git master

- Celebrate
