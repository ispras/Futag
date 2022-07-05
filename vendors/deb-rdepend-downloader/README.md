# deb-rdepend-downloader
This bash script is for downloading Debian rdepended packages of given package.
The script will create folder of package name and subfolder (named "dependencies" - feel free to change it in script) for depended packages.
 
## Usage:
```bash
$ get-rdepend-pkgs.sh [package name]
```
Example:
```bash
$ get-rdepend-pkgs.sh curl
```
