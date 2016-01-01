#!/bin/sh

autoreconf -iv
if command -v doxygen >/dev/null 2>&1
then
    echo "generating doxygen documentation"
    doxygen doc/Doxyfile
fi

