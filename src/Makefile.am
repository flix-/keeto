lib_LTLIBRARIES = pox509-base.la \
                  pox509-audit.la \
                  pox509-validate.la
include_HEADERS = pox509-log.h \
                  pox509-util.h

pox509_base_la_SOURCES = pox509-base.c \
                         pox509-config.h \
                         pox509-config.c \
                         pox509-ldap.h \
                         pox509-ldap.c \
                         pox509-log.h \
                         pox509-log.c \
                         pox509-util.h \
                         pox509-util.c \
                         pox509-x509.h \
                         pox509-x509.c
pox509_base_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pox509_base_la_LIBADD = ${LIBADD_BASE}

pox509_audit_la_SOURCES = pox509-audit.c \
                          pox509-log.h \
                          pox509-log.c \
                          pox509-util.h \
                          pox509-util.c
pox509_audit_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pox509_audit_la_LIBADD = ${LIBADD_AUDIT}

pox509_validate_la_SOURCES = pox509-validate.c \
                             pox509-log.h \
                             pox509-log.c \
                             pox509-util.h \
                             pox509-util.c
pox509_validate_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pox509_validate_la_LIBADD = ${LIBADD_VALIDATE}

