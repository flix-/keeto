# Prelude.
AC_PREREQ([2.69])
AC_INIT([keeto], [0.2.0-beta], [seroland86@gmail.com], [],
    [https://github.com/flix-/keeto])
AC_LANG([C])
AC_CONFIG_SRCDIR([src/pox509-util.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([gnu subdir-objects -Wall -Werror])
AM_PROG_AR
LT_INIT([disable-static dlopen pic-only])

# Checks for programs.
AC_PROG_CC

# define preprocessor symbols
AC_DEFINE(DEBUG, 0)

# Checks for libraries.
PKG_CHECK_MODULES([libcheck], [check >= 0.9.9], [],
    [AC_MSG_ERROR([cannot find libcheck (>= 0.9.9)])])
PKG_CHECK_MODULES([libconfuse], [libconfuse >= 2.7], [],
    [AC_MSG_ERROR([cannot find libconfuse (>= 2.7)])])
PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.1e], [],
    [AC_MSG_ERROR([cannot find libcrypto (>= 1.0.1e)])])
AC_CHECK_LIB([ldap], [ldap_sasl_bind_s], [],
    [AC_MSG_ERROR([cannot find libldap])])
AC_CHECK_LIB([lber], [ber_free], [], [AC_MSG_ERROR([cannot find liblber])])
AC_CHECK_LIB([pam], [pam_start], [], [AC_MSG_ERROR([cannot find libpam])])
AC_SUBST([LIBS], [ ])

AC_SUBST([LIBADD_BASE], ["-lpam ${libconfuse_LIBS} -lldap -llber \
    ${libcrypto_LIBS}"])
AC_SUBST([LIBADD_AUDIT], ["-lpam ${libconfuse_LIBS} -lldap -llber \
    ${libcrypto_LIBS}"])
AC_SUBST([LDADD_CHECK], ["-lpam ${libcheck_LIBS} ${libconfuse_LIBS} -lldap \
    -llber ${libcrypto_LIBS}"])

# set compiler flags
AC_SUBST([CFLAGS], ["-Wall -std=gnu99 -pedantic-errors"])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Output files.
#AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT

