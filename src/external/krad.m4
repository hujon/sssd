AC_CHECK_HEADER(krad.h,
    [AC_CHECK_LIB(
        krad,
        krad_attrset_new,
        [],
        [AC_MSG_ERROR([libkrad missing krad_attrset_new])],
        [-lverto -lkrb5]) ],
    [AC_MSG_ERROR([krad.h header file missing])],
    )
