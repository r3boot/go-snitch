DAEMON = go-snitch
UI = go-snitch-ui

BUILD_DIR = ./build
COMMANDS_DIR = ./commands
PREFIX = /usr/local

all: ${DAEMON} ${UI}

${DAEMON}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	go build -v -o "${BUILD_DIR}/${DAEMON}" "${COMMANDS_DIR}/${DAEMON}/main.go"

${UI}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	go build -v -o "${BUILD_DIR}/${UI}" "${COMMANDS_DIR}/${UI}/main.go"

install:
	install -o root -g root -m 0755 build/go-snitch \
		${PREFIX}/bin/go-snitch
	install -o root -g root -m 0755 build/go-snitch-ui \
		${PREFIX}/bin/go-snitch-ui
	install -o root -g root -m 0644 files/net.as65342.GoSnitch.conf \
		/etc/dbus-1/system.d/net.as65342.GoSnitch.conf

clean:
	[ -d "${BUILD_DIR}" ] && rm -rf ${BUILD_DIR} || true
