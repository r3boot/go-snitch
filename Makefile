DAEMON = go-snitch
UI = go-snitch-ui

BUILD_DIR = ./build
COMMANDS_DIR = ./commands

all: ${DAEMON} ${UI}

${DAEMON}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	go build -v -o "${BUILD_DIR}/${DAEMON}" "${COMMANDS_DIR}/${DAEMON}/main.go"

${UI}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	go build -v -o "${BUILD_DIR}/${UI}" "${COMMANDS_DIR}/${UI}/main.go"

clean:
	[ -d "${BUILD_DIR}" ] && rm -rf ${BUILD_DIR} || true
