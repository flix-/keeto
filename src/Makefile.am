lib_LTLIBRARIES = pam_keeto.la \
                  pam_keeto_audit.la

pam_keeto_la_SOURCES = keeto.c \
                       keeto-config.h \
                       keeto-config.c \
                       keeto-error.h \
                       keeto-error.c \
                       keeto-ldap.h \
                       keeto-ldap.c \
                       keeto-log.h \
                       keeto-log.c \
                       keeto-openssl.h \
                       keeto-openssl.c \
                       keeto-util.h \
                       keeto-util.c \
                       keeto-x509.h \
                       keeto-x509.c
pam_keeto_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_keeto_la_LIBADD = ${LIBADD_BASE}

pam_keeto_audit_la_SOURCES = keeto-audit.c \
                             keeto-config.h \
                             keeto-config.c \
                             keeto-error.h \
                             keeto-error.c \
                             keeto-log.h \
                             keeto-log.c \
                             keeto-util.h \
                             keeto-util.c \
                             keeto-x509.h \
                             keeto-x509.c
pam_keeto_audit_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_keeto_audit_la_LIBADD = ${LIBADD_AUDIT}

