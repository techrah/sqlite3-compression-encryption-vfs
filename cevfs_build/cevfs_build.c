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

typedef uint8_t u8;

extern const char *fileTail(const char *z);
extern void *sqlite3HexToBlob(sqlite3 *db, const char *z, int n);

int main(int argc, const char * argv[]) {
  if( argc != 4 ){
    printf("Usage: %s UNCOMPRESSED COMPRESSED KEY\n", fileTail(argv[0]));
    printf("  UNCOMPRESSED: URI of uncompressed SQLite DB file.\n");
    printf("  COMPRESSED:   URI of new compressed DB with optional ?block_size=<block_size>\n");
    printf("  KEY:          Encryption key in the form: x'<hex1><hex2>...<hex32>'\n");
    return EXIT_FAILURE;
  }

  int rc;

  // This context will be passed to xAutoDetect and the functions defined within.
  struct context ctx;

  // Convert encryption key string to hex blob.
  // This assumes that the key is in the form of x'<hex-string>'
  // You should, of course, implement proper error checking.
  const char *key = arvg[3]+2;
  char *keyBytes = sqlite3HexToBlob(NULL, key, strlen(key)-1);

  ctx.pKey   = keyBytes;           // 32-bit encryption hex key
  ctx.nKeySz = kCCKeySizeAES256;   // key size in bytes
  ctx.nIvSz  = kCCBlockSizeAES128; // size of IV in bytes

  // If you will be using the VFS name to determine how you set up your xMethods,
  // you may want to pass the VFS name as a command line parameter as well.
  // For now, we'll just pass "CEVFS-default".
  rc = cevfs_build(argv[1], argv[2], "CEVFS-default", &ctx, cevfsAutoDetect);
  return rc;
}
