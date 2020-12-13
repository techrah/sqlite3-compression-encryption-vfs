/**
CEVFS - Compression & Encryption VFS
cevfs_mod (module activation)

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

#include "xMethods.c"

struct context ctx;

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

void sqlite3_activate_cerod(const char *key) {
  char *pKeyBytes = hexToBlob(key+2, strlen(key+2)-1);

  ctx.pKey   = pKeyBytes;          // 32-bit encryption hex key
  ctx.nKeySz = kCCKeySizeAES256;   // key size in bytes
  ctx.nIvSz  = kCCBlockSizeAES128; // size of IV in bytes

  cevfs_create_vfs("cevfs-cerod", NULL, &ctx, cevfsAutoDetect, 1);
}
