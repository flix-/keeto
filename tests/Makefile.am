TESTS = pox509-check
check_PROGRAMS = pox509-check
pox509_check_SOURCES = pox509-check-config.h \
                       pox509-check-config.c \
                       pox509-check-log.h \
                       pox509-check-log.c \
                       pox509-check-util.h \
                       pox509-check-util.c \
                       pox509-check-x509.h \
                       pox509-check-x509.c \
                       pox509-check-main.c \
                       ../src/pox509-config.h \
                       ../src/pox509-config.c \
                       ../src/pox509-error.h \
                       ../src/pox509-error.c \
                       ../src/pox509-log.h \
                       ../src/pox509-log.c \
                       ../src/pox509-util.h \
                       ../src/pox509-util.c \
                       ../src/pox509-x509.h
pox509_check_LDADD = ${LDADD_CHECK}
pox509_check_CPPFLAGS = -DCONFIGSDIR="\"${srcdir}/configs\"" \
                        -DFILEREADABLEDIR="\"${srcdir}/file_readable\"" \
                        -DKEYSTORERECORDSDIR="\"${srcdir}/keystore_records\"" \
                        -DX509CERTSDIR="\"${srcdir}/certificates\"" \
                        -DCACERTSDIR="\"${srcdir}/ca_certificates\""

