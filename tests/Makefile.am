TESTS = keeto-check
check_PROGRAMS = keeto-check
keeto_check_SOURCES = keeto-check.c \
                      keeto-check-config.h \
                      keeto-check-config.c \
                      keeto-check-log.h \
                      keeto-check-log.c \
                      keeto-check-util.h \
                      keeto-check-util.c \
                      keeto-check-x509.h \
                      keeto-check-x509.c \
                      ../src/keeto-config.h \
                      ../src/keeto-config.c \
                      ../src/keeto-error.h \
                      ../src/keeto-error.c \
                      ../src/keeto-log.h \
                      ../src/keeto-log.c \
                      ../src/keeto-openssl.h \
                      ../src/keeto-openssl.c \
                      ../src/keeto-util.h \
                      ../src/keeto-util.c \
                      ../src/keeto-x509.h
keeto_check_LDADD = ${LDADD_CHECK}
keeto_check_CPPFLAGS = -DCONFIGSDIR="\"${srcdir}/configs\"" \
                       -DFILEREADABLEDIR="\"${srcdir}/file_readable\"" \
                       -DKEYSTORERECORDSDIR="\"${srcdir}/keystore_records\"" \
                       -DFINGERPRINTSDIR="\"${srcdir}/fingerprints\"" \
                       -DX509CERTSDIR="\"${srcdir}/certificates\"" \
                       -DCERTSTOREDIR="\"${srcdir}/cert_store\""

