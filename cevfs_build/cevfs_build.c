/**
CEVFS - Compression & Encryption VFS
cevfs_build

Copyright (c) 2016 Ryan Homer, Murage Inc.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "cevfs.h"
#include "xMethods.c"

extern const char *fileTail(const char *z);
typedef unsigned char u8;

/*
** Taken from SQLite source code.
** Check to see if this machine uses EBCDIC.  (Yes, believe it or
** not, there are still machines out there that use EBCDIC.)
*/
#if 'A' == '\301'
# define SQLITE_EBCDIC 1
#else
# define SQLITE_ASCII 1
#endif

/*
** Taken from SQLite source code.
** Translate a single byte of Hex into an integer.
** This routine only works if h really is a valid hexadecimal
** character:  0..9a..fA..F
*/
static u8 hexToInt(int h){
  assert( (h>='0' && h<='9') ||  (h>='a' && h<='f') ||  (h>='A' && h<='F') );
#ifdef SQLITE_ASCII
  h += 9*(1&(h>>6));
#endif
#ifdef SQLITE_EBCDIC
  h += 9*(1&~(h>>4));
#endif
  return (u8)(h & 0xf);
}

/*
** Taken from SQLite source code.
** Convert a BLOB literal of the form "x'hhhhhh'" into its binary
** value.  Return a pointer to its binary value.  Space to hold the
** binary value has been obtained from malloc and must be freed by
** the calling routine.
*/
static void *hexToBlob(const char *z, int n){
  char *zBlob;
  int i;

  zBlob = (char *)malloc(n/2 + 1);
  n--;
  if( zBlob ){
    for(i=0; i<n; i+=2){
      zBlob[i/2] = (hexToInt(z[i])<<4) | hexToInt(z[i+1]);
    }
    zBlob[i/2] = 0;
  }
  return zBlob;
}

// This context will be passed to xAutoDetect and the functions defined within.
struct context ctx;

int main(int argc, const char * argv[]) {
  if( argc != 5 ){
    printf("Usage: %s UNCOMPRESSED COMPRESSED KEY\n", fileTail(argv[0]));
    printf("  UNCOMPRESSED: URI of uncompressed SQLite DB file.\n");
    printf("  COMPRESSED:   URI of new compressed DB with optional ?block_size=<block_size>\n");
    printf("  VFS_NAME:     Name of VFS to embed in database file.\n");
    printf("  KEY:          Encryption key in the form: x'<hex1><hex2>...<hex32>'\n");
    return EXIT_FAILURE;
  }

  int rc;

  // Convert encryption key string to hex blob.
  // This assumes that the key is in the form of x'<hex-string>'
  // You should, of course, implement proper error checking.
  const char *key = argv[4]+2;
  char *keyBytes = hexToBlob(key, (int)strlen(key)-1);

  ctx.pKey   = keyBytes;           // 32-bit encryption hex key
  ctx.nKeySz = kCCKeySizeAES256;   // key size in bytes
  ctx.nIvSz  = kCCBlockSizeAES128; // size of IV in bytes

  // You can use the VFS name to determine how you set up your xMethods,
  // so we pass the VFS name as a command line parameter as well.
  rc = cevfs_build(argv[1], argv[2], argv[3], &ctx, cevfsAutoDetect);
  return rc;
}
