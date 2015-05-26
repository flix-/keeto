TESTS = pam_openssh_x509_check
check_PROGRAMS = pam_openssh_x509_check
pam_openssh_x509_check_SOURCES = pam_openssh_x509_check_main.c \
                                 pam_openssh_x509_check_config.c \
                                 pam_openssh_x509_check_util.c \
                                 pam_openssh_x509_check.h \
                                 ../src/pam_openssh_x509_util.c
pam_openssh_x509_check_LDADD = ${LDADD_CHECK}
pam_openssh_x509_check_CPPFLAGS = -DCACERTSDIR="\"${srcdir}/ca_certificates\"" \
                                  -DX509CERTSDIR="\"${srcdir}/validate_x509\"" \
                                  -DCONFIGSDIR="\"${srcdir}/init_and_parse_config\"" \
                                  -DKEYSDIR="\"${srcdir}/pkey_to_authorized_keys\"" \
                                  -DREADABLEFILESDIR="\"${srcdir}/is_readable_file\""

