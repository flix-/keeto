TESTS = pox509-check
check_PROGRAMS = pox509-check
pox509_check_SOURCES = pox509-check-main.c \
                       pox509-check-config.c \
                       pox509-check-util.c \
                       pox509-check.h \
                       ../src/pox509-util.c
pox509_check_LDADD = ${LDADD_CHECK}
pox509_check_CPPFLAGS = -DCACERTSDIR="\"${srcdir}/ca_certificates\"" \
                        -DX509CERTSDIR="\"${srcdir}/validate_x509\"" \
                        -DCONFIGSDIR="\"${srcdir}/init_and_parse_config\"" \
                        -DKEYSDIR="\"${srcdir}/pkey_to_authorized_keys\"" \
                        -DREADABLEFILESDIR="\"${srcdir}/is_readable_file\""

