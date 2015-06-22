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
                       ../src/pox509-log.h \
                       ../src/pox509-log.c \
                       ../src/pox509-util.h \
                       ../src/pox509-util.c
pox509_check_LDADD = ${LDADD_CHECK}
pox509_check_CPPFLAGS = -DCACERTSDIR="\"${srcdir}/ca_certificates\"" \
                        -DX509CERTSDIR="\"${srcdir}/validate_x509\"" \
                        -DCONFIGSDIR="\"${srcdir}/init_and_parse_config\"" \
                        -DKEYSDIR="\"${srcdir}/pkey_to_authorized_keys\"" \
                        -DREADABLEFILESDIR="\"${srcdir}/is_readable_file\""

