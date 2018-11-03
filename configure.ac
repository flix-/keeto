# prelude.
AC_PREREQ([2.69])
AC_INIT([keeto], [0.4.1-beta], [seroland86@gmail.com], [], [https://keeto.io])
AC_LANG([C])
AC_CONFIG_SRCDIR([src/keeto-pam.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([gnu subdir-objects -Wall -Werror])
AM_PROG_AR
LT_INIT([disable-static dlopen pic-only])

# checks for programs.
AC_PROG_CC

# add for legacy reasons.
AM_PROG_CC_C_O

# enable/disable debug build
AC_ARG_ENABLE([debug],
[  --enable-debug          Turn on debugging],
[case "${enableval}" in
  yes) debug="true" ;;
  no)  debug="false" ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug="false"])

AS_IF([test "x${debug}" = "xtrue"], [AC_DEFINE(DEBUG, 1)], [AC_DEFINE(DEBUG, 0)])
AM_CONDITIONAL([DEBUG], [test "x${debug}" = "xtrue"])

# checks for libraries.
PKG_CHECK_MODULES([libcheck], [check >= 0.9.9], [],
    [AC_MSG_ERROR([cannot find libcheck (>= 0.9.9)])])
PKG_CHECK_MODULES([libconfuse], [libconfuse >= 2.7], [],
    [AC_MSG_ERROR([cannot find libconfuse (>= 2.7)])])
PKG_CHECK_MODULES([libssl], [libssl >= 1.0], [],
    [AC_MSG_ERROR([cannot find libssl (>= 1.0)])])
PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0], [],
    [AC_MSG_ERROR([cannot find libcrypto (>= 1.0)])])
AC_CHECK_LIB([ldap], [ldap_sasl_bind_s], [],
    [AC_MSG_ERROR([cannot find libldap])])
AC_CHECK_LIB([lber], [ber_free], [], [AC_MSG_ERROR([cannot find liblber])])
AC_CHECK_LIB([pam], [pam_start], [], [AC_MSG_ERROR([cannot find libpam])])
AC_SUBST([LIBS], [ ])

AC_SUBST([LIBADD_BASE], ["-lpam ${libconfuse_LIBS} -lldap -llber \
    ${libssl_LIBS} ${libcrypto_LIBS}"])
AC_SUBST([LIBADD_AUDIT], ["-lpam ${libconfuse_LIBS} -lldap -llber \
    ${libssl_LIBS} ${libcrypto_LIBS}"])
AC_SUBST([LIBADD_DEBUG], ["-lpam ${libconfuse_LIBS} -lldap -llber \
    ${libssl_LIBS} ${libcrypto_LIBS}"])
AC_SUBST([LDADD_CHECK], ["-lpam ${libcheck_LIBS} ${libconfuse_LIBS} -lldap \
    -llber ${libssl_LIBS} ${libcrypto_LIBS}"])

# set compiler flags
AS_IF([test "x${debug}" = "xtrue"],
    AC_SUBST([CFLAGS], ["-Wall -pedantic-errors -std=gnu99 -O0 -ggdb --coverage"]),
    AC_SUBST([CFLAGS], ["-Wall -pedantic-errors -std=gnu99"])
)

# checks for header files.

# checks for typedefs, structures, and compiler characteristics.

# checks for library functions.

# output files.
#AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_OUTPUT

