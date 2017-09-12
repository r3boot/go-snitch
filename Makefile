DAEMON = go-snitch-daemon
APPLET = go-snitch-applet
MANAGE = go-snitch-manage

BUILD_DIR = ./build
COMMANDS_DIR = ./cmd
HELPERS_DIR = ./helpers
PREFIX = /usr/local

QT_DIR = /usr/lib/qt
QT_QMAKE_DIR = /usr/bin

all: ${DAEMON} ${APPLET} ${MANAGE}

${DAEMON}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	go build -v -o "${BUILD_DIR}/${DAEMON}" "${COMMANDS_DIR}/${DAEMON}/main.go"

${APPLET}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	cd ${COMMANDS_DIR}/${APPLET} ; qtdeploy build desktop
	install -m 0755 ${COMMANDS_DIR}/${APPLET}/deploy/linux/${APPLET} \
		${BUILD_DIR}/${APPLET}

${MANAGE}:
	[ -d "${BUILD_DIR}" ] || mkdir -p "${BUILD_DIR}"
	cd ${COMMANDS_DIR}/${MANAGE} ; qtdeploy build desktop
	install -m 0755 ${COMMANDS_DIR}/${MANAGE}/deploy/linux/${MANAGE} \
    	${BUILD_DIR}/${MANAGE}

install:
	strip ${BUILD_DIR}/${DAEMON}
	install -o root -g root -m 0755 ${BUILD_DIR}/${DAEMON} \
		${PREFIX}/bin/${DAEMON}
	strip ${BUILD_DIR}/${APPLET}
	install -o root -g root -m 0755 ${BUILD_DIR}/${APPLET} \
		${PREFIX}/bin/${APPLET}
	strip ${BUILD_DIR}/${MANAGE}
	install -o root -g root -m 0755 ${BUILD_DIR}/${MANAGE} \
		${PREFIX}/bin/${MANAGE}
	install -o root -g root -m 0644 files/net.as65342.GoSnitch.conf \
		/etc/dbus-1/system.d/net.as65342.GoSnitch.conf

clean:
	[ -d "${BUILD_DIR}" ] && rm -rf ${BUILD_DIR} || true
	[ -d "${COMMANDS_DIR}/${APPLET}/deploy" ] \
		&& rm -rf "${COMMANDS_DIR}/${APPLET}/deploy" || true
	rm -f "${COMMANDS_DIR}/${APPLET}/rcc"* || true
	[ -d "${COMMANDS_DIR}/${MANAGE}/deploy" ] \
        && rm -rf "${COMMANDS_DIR}/${MANAGE}/deploy" || true
