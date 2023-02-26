setup:
	mkdir bin/

build:
	export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig"
	cd src && \
	go build -o ../bin/macos_scanner .

build_linux:
	docker build -t scanner_build_linux_image -f Dockerfile.linux --progress=plain . && \
	docker run --name "scanner_build_linux_container" scanner_build_linux_image && \
	docker cp scanner_build_linux_container:/go/src/project/scanner/malware_scanner ./bin/linux_x86_64_scanner && \
	docker rm scanner_build_linux_container && \
	docker image rm scanner_build_linux_image

build_win32:
	docker build -t scanner_build_windows_image_32 -f Dockerfile.win32 --progress=plain . && \
	docker run --name "scanner_build_windows_container_32" scanner_build_windows_image_32 && \
	docker cp scanner_build_windows_container_32:/go/bin/scanner_windows32.exe ./bin/windows_x86_32_scanner.exe && \
	docker rm scanner_build_windows_container_32 && \
	docker image rm scanner_build_windows_image_32

build_win64:
	docker build -t scanner_build_windows_image_64 -f Dockerfile.win64 --progress=plain . && \
	docker run --name "scanner_build_windows_container_64" scanner_build_windows_image_64 && \
	docker cp scanner_build_windows_container_64:/go/bin/scanner_windows64.exe ./bin/windows_x86_64_scanner.exe && \
	docker rm scanner_build_windows_container_64 && \
	docker image rm scanner_build_windows_image_64