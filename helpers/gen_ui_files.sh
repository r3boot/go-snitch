#!/bin/sh

if [[ ! -d .git ]]; then
    echo "Please run this script from the top level directory"
    exit 1
fi

find ./lib/ui -type f -name *.glade | while read GLADE_FILE; do
    DIRNAME="$(dirname ${GLADE_FILE})"
    OUTPUT="${DIRNAME}/glade.go"
    MODULE="$(basename ${DIRNAME})"
    if [[ -f "${OUTPUT}" ]]; then
        rm -f "${OUTPUT}"
    fi
    echo "Generating glade.go for ${MODULE} module"
    echo "package ${MODULE}" > ${OUTPUT}
    echo -n 'const GLADE_DATA string = `' >> ${OUTPUT}
    cat "${GLADE_FILE}" >> ${OUTPUT}
    echo '`' >> ${OUTPUT}
done