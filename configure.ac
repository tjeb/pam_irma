#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([PAM_IRMA], [0.1.0], [puiterwijk@gmail.com])
AC_CONFIG_SRCDIR([pam_irma.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX[g++]
CC=g++
CXX=g++

AC_CHECK_LIB([pam], [pam_set_item], [], AC_MSG_ERROR([Cannot find pam library]))

AC_ARG_ENABLE([nfc],
              AS_HELP_STRING([--enable-nfc],
                             [Compile the pam_irma_nfc.so module]),
              [],
              [enable_nfc="yes"]
             )
AS_IF([test "x$enable_nfc" != "xno"],
      [
        AC_CHECK_LIB([nfc], [nfc_init], [], AC_MSG_ERROR([Cannot find nfc library])),
        AC_SUBST(NFC_SO, "pam_irma_nfc.so")
        AC_SUBST(INSTALL_NFC, "install_nfc")
        AC_SUBST(UNINSTALL_NFC, "uninstall_nfc")
      ])

AC_ARG_ENABLE([pcsc],
              AS_HELP_STRING([--enable-pcsc],
                             [Compile the pam_irma_pcsc.so module]),
              [],
              [enable_pcsc="yes"]
             )
AS_IF([test "x$enable_pcsc" != "xno"],
      [
        AC_CHECK_LIB([pcsclite], [SCardConnect], [], AC_MSG_ERROR([Cannot find pcsclite library]))
        AC_SUBST(PCSC_SO, "pam_irma_pcsc.so")
        AC_SUBST(INSTALL_PCSC, "install_pcsc")
        AC_SUBST(UNINSTALL_PCSC, "uninstall_pcsc")
      ])

# Make sure one of them is enabled
AS_IF([test "x$enable_nfc" = "xno"],
      AS_IF([test "x$enable_pcsc" = "xno"],
            AC_MSG_ERROR("You probably want to enable either nfc or pcsc")))

AC_ARG_WITH([silvia],
            AS_HELP_STRING([--with-silvia],
                           [Specify path of silvia library]))

AS_IF([test "x$with_silvia" = "xno"],
      AC_MSG_ERROR([Need silvia library and headers]))

AS_IF([test "x$have_foo" != "xyes"],
      [CFLAGS="$CFLAGS -I$withval/include"
       LDFLAGS="$LDFLAGS -L$withval/lib"
      ],
      [])

AC_ARG_WITH([pam-libdir],
            AS_HELP_STRING([--pam-libdir],
                           [location to install PAM modules]),
            [pam_libdir=$withval],
            [pam_libdir=/usr/lib64/security/]
           )
AC_SUBST(PAM_LIBDIR, $pam_libdir)

# Check if the silvia library is available.
# Not using AC_CHECK_LIB since autoconf does not seem to like c++ libs
LDFLAGS="$LDFLAGS -lsilvia"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[@%:@include <silvia/silvia_types.h>
                                  
                                ]],
                                [silvia_attr_t sat;])],
               [], [AC_MSG_ERROR("Cannot find silvia library")])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo ""
echo "Build pam_irma_nfc.so module: $enable_nfc"
echo "Build pam_irma_pcsc.so module: $enable_pcsc"
