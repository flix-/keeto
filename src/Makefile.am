lib_LTLIBRARIES = pam_pox509.la \
                  pam_pox509_audit.la
include_HEADERS = pox509-error.h \
                  pox509-log.h \
                  pox509-util.h

pam_pox509_la_SOURCES = pox509.c \
                        pox509-config.h \
                        pox509-config.c \
                        pox509-error.h \
                        pox509-error.c \
                        pox509-ldap.h \
                        pox509-ldap.c \
                        pox509-log.h \
                        pox509-log.c \
                        pox509-util.h \
                        pox509-util.c \
                        pox509-x509.h \
                        pox509-x509.c
pam_pox509_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_pox509_la_LIBADD = ${LIBADD_BASE}

pam_pox509_audit_la_SOURCES = pox509-audit.c \
                              pox509-config.h \
                              pox509-config.c \
                              pox509-error.h \
                              pox509-error.c \
                              pox509-log.h \
                              pox509-log.c \
                              pox509-util.h \
                              pox509-util.c \
                              pox509-x509.h \
                              pox509-x509.c
pam_pox509_audit_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_pox509_audit_la_LIBADD = ${LIBADD_AUDIT}

