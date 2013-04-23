AC_CHECK_HEADER(verto.h,
    [AC_CHECK_LIB(
        verto,
        verto_new,
        [],
        [AC_MSG_ERROR([verto missing verto_new])],
        []) ],
    [AC_MSG_ERROR([verto.h header file missing])],
    )
