# Malware Scanner
A malware scanner for YARA rules for Windows, Linux and MacOS written in Golang. It can scan `VSS` snapshots on Windows, leading to fewer `could not open file` errors. 
## Usage
```sh
malware-scanner -h # on linux & macos
```

```
         _                                         _                    _ 
        | |                                       | |                  | |
        | |__   __ _ _ __ ___  _ __ ___   ___ _ __| |__   ___  __ _  __| |
        | '_ \ / _' | '_  '_ \| '_  '_ \ / _ \ '__| '_ \ / _ \/ _  |/ _  |
        | | | | (_| | | | | | | | | | | |  __/ |  | | | |  __/ (_| | (_| |
        |_| |_|\__,_|_| |_| |_|_| |_| |_|\___|_|  |_| |_|\___|\__,_|\__,_|


usage:  scanner [OPTIONS] [DIR|FILE...]
Scan files/directories against YARA rules.
  -L string
        Logging Path (default: stdout)
  -O string
        Output Path (default: stdout)
  -R string
        YARA rules File|Directory Path
  -V string
        YARA rule variables file path (.yml)
  -d    Debug mode
  -s    Strict mode
  -t int
        Number of threads (for scanning) (default 16)
  -v    Verbose mode


```

```sh
windows_x86_64_scanner.exe -h # on windows
```

```
         _                                         _                    _
        | |                                       | |                  | |
        | |__   __ _ _ __ ___  _ __ ___   ___ _ __| |__   ___  __ _  __| |
        | '_ \ / _' | '_  '_ \| '_  '_ \ / _ \ '__| '_ \ / _ \/ _  |/ _  |
        | | | | (_| | | | | | | | | | | |  __/ |  | | | |  __/ (_| | (_| |
        |_| |_|\__,_|_| |_| |_|_| |_| |_|\___|_|  |_| |_|\___|\__,_|\__,_|


usage:  scanner.exe [OPTIONS] [DIR|FILE|DRIVE...]
Scan files/directories/drives against YARA rules. Option to run a scan against a VSS snapshot.
  -E string
        YARA rule variables file path (.yml)
  -L string
        Logging Path (default: stdout)
  -O string
        Output Path (default: stdout)
  -R string
        YARA rules File or Directory
  -T int
        VSS - Timeout for snapshot creation (min 180s) (default 180)
  -V    VSS - Scan snapshot
  -VSS string
        VSS - Path create VSS symlink
  -d    Debug mode
  -f    VSS - Force snapshot creation. WARNING: can replace existing snapshots
  -kL
        VSS - Keep symlink
  -kV
        VSS - Keep snapshot
  -s    Strict mode
  -t int
        Number of threads (for scanning) (default 16)
  -v    Verbose mode

```

## Cross Compilation
Docker is used for cross compilation. You can build the docker image with:
```sh
make build_linux # build linux
make build_win32 # build windows 32bit
make build_win64 # build windows 64bit
```
Exectuables will be dropped in the `bin` folder. Run this to create the folder:

```sh
make setup
```

## MacOS Build
Have at least yara 4.2.0 installed. You might need to link to libcrypto library. If installed with brew, you can do this:
```
export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig"
```