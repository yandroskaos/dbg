#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "../inc/dbg.h"

////////////////
//DO NOT TOUCH//
////////////////

//Helpers
#define A1(X) #X
#define A(X) A1(X)
#define VER_ANSI1(V, X, Y, Z) V ## . ## X ## . ## Y ## . ## Z
#define VER_ANSI(V, X, Y, Z) A(VER_ANSI1(V, X, Y, Z))
#define W1(X) L ## X
#define W(X) W1(X)
#define VER_UNICODE(V, X, Y, Z) W(VER_ANSI(V, X, Y, Z))


//Version strings
#define VERSION_A VER_ANSI(VER_MAJOR, VER_MINOR, VER_TYPE, VER_BUILD)
#define VERSION_W W(VERSION_A)


//Resources//

//Binary
#define RC_FILE    VER_MAJOR, VER_MINOR, VER_TYPE, VER_BUILD
#define RC_PRODUCT VER_MAJOR, VER_MINOR, VER_TYPE, VER_BUILD

//Strings
#define RC_FILE_STRING VALUE "FileVersion", VERSION_A "\0"
#define RC_PRODUCT_STRING VALUE "ProductVersion", VERSION_A "\0"

#endif
