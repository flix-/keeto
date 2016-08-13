lib_LTLIBRARIES = pox509-base.la
include_HEADERS = pox509-log.h \
                  pox509-util.h

pox509_base_la_SOURCES = pox509-base.c \
                         pox509-config.h \
                         pox509-config.c \
                         pox509-ldap.h \
                         pox509-ldap.c \
                         pox509-log.h \
                         pox509-log.c \
                         pox509-result.h \
                         pox509-result.c \
                         pox509-util.h \
                         pox509-util.c
pox509_base_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pox509_base_la_LIBADD = ${LIBADD_BASE}

