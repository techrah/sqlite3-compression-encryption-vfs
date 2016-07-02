//
//  main.c
//  sqlite_compress_test
//
//  Created by Ryan Homer on 23/1/2016.
//  Copyright © 2016 Murage Inc. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

#include "cevfs.h"
#include "sqlite3.h"

#define SQL_TEST_WRITE 1
#define SQL_TEST_READ 1
#define SQL_DEBUG_OUTPUT 1
#define VFS_NAME "example"

static const char *dbFile = "test.db";
static const char *dbUri  = "file:test.db?block_size=2048"; // lower level page size

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i=0; i<argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int xOut(const char * msg, void * out) {
  fputs(msg, out);
  return 0;
}

struct context {
  void *pKey;
  int   nKeySz;
  int   nIvSz;
};

static void random_bytes(unsigned char *buf, int num){
  int i;
  int j = num/4;
  uint32_t *dwbuf = (uint32_t *)buf;

  srandomdev();
  for( i=0; i<j; i++ ){
    *(dwbuf+i) = (u_int32_t)random();
  }
}

int cevfsCompressBound(void *p, size_t nByte) {
  return (int)compressBound(nByte);
}

int cevfsCompress(void *p, char *aDest, size_t *pnDest, char *aSrc, size_t nSrc) {
  uLongf n = *pnDest;             /* In/out buffer size for compress() */
  int rc;                         /* compress() return code */
  
  rc = compress((Bytef*)aDest, &n, (Bytef*)aSrc, nSrc);
  *pnDest = (int)n;
  return (rc==Z_OK);
}

int cevfsUncompress(void *p, char *aDest, size_t *pnDest, char *aSrc, size_t nSrc) {
  uLongf n = *pnDest;             /* In/out buffer size for uncompress() */
  int rc;                         /* uncompress() return code */
  
  rc = uncompress((Bytef*)aDest, &n, (Bytef*)aSrc, nSrc);
  *pnDest = (int)n;
  return (rc==Z_OK);
}

int cevfsEncrypt(
  void *pEncryptCtx,
  const void *pDataIn,
  size_t nDataInSize,
  void *pIvOut,
  void **ppDataOut,
  size_t *nDataSizeOut,
  void *sqlite3_malloc(int n)
){
  struct context *pCtx = (struct context *)pEncryptCtx;
  random_bytes(pIvOut, pCtx->nIvSz);

  /* According to CCCryptor manpage: "For block ciphers, the output size will always be less than or
     equal to the input size plus the size of one block." However, there seems to be a bug as normally
     CCCrypt fails with error code kCCBufferTooSmall when the output buffer size is too small, can
     crash when size is exactly input size plus size of one block. It works with just 1 more byte.
     REF: https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html */
  size_t nOutSz = nDataInSize+kCCBlockSizeAES128+1;
  *ppDataOut = sqlite3_malloc((int)nOutSz);

  CCCryptorStatus ccStatus = CCCrypt(
    kCCEncrypt,            // enc/dec
    kCCAlgorithmAES128,    // algorithm
    kCCOptionPKCS7Padding, // options: kCCOptionPKCS7Padding, kCCOptionECBMode, 0 = no padding
    pCtx->pKey,            // 256-bit (32-byte) key
    pCtx->nKeySz,          // key length (bytes)
    pIvOut,                // const void *iv
    pDataIn,               // const void *dataIn
    nDataInSize,           // data-in length
    *ppDataOut,            // dataOut; result is written here.
    nOutSz,                // The size of the dataOut buffer in bytes
    nDataSizeOut           // On successful return, the number of bytes written to dataOut.
  );
  return (ccStatus==kCCSuccess);
}

int cevfsDecrypt(void *pDecryptCtx,
  const void *pDataIn,
  size_t nDataInSize,
  const void *pIvIn,
  void *pDataOut,
  size_t nDataBufferSizeOut,
  size_t *nDataSizeOut
){
  struct context *pCtx = (struct context *)pDecryptCtx;
  CCCryptorStatus ccStatus = CCCrypt(
    kCCDecrypt,            // enc/dec
    kCCAlgorithmAES128,    // algorithm
    kCCOptionPKCS7Padding, // options: kCCOptionPKCS7Padding, kCCOptionECBMode, 0 = no padding
    pCtx->pKey,            // 256-bit (32-byte) key
    pCtx->nKeySz,          // key length (bytes)
    pIvIn,                 // const void *iv
    pDataIn,               // const void *dataIn
    nDataInSize,           // data-in length
    pDataOut,              // dataOut; result is written here.
    nDataBufferSizeOut,    // The size of the dataOut buffer in bytes
    nDataSizeOut           // On successful return, the number of bytes written to dataOut.
  );
  return (ccStatus==kCCSuccess);
}

int cevfsAutoDetect(void *pCtx, const char *zFile, const char *zHdr, size_t *pEncIvSz, CevfsMethods *pMethods) {
  *pEncIvSz = kCCBlockSizeAES128;
  pMethods->xCompressBound = cevfsCompressBound;
  pMethods->xCompress = cevfsCompress;;
  pMethods->xUncompress = cevfsUncompress;
  pMethods->xEncrypt = cevfsEncrypt;
  pMethods->xDecrypt = cevfsDecrypt;
  return SQLITE_OK;
}

void removeDbFile(const char *dbFile){
  char zFile[256];
  char buf[256];
  strcpy(zFile, dbFile);
  char *p = strstr(zFile, "?");
  if( p ) *p = '\0';
  sprintf(buf, "%s-journal", zFile);
  remove(zFile);
  remove(buf);
}

int testWrite(char* zErrMsg){
  sqlite3 *db;
  int rc;
  removeDbFile(dbFile);
  if( (rc = sqlite3_open_v2(dbUri, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, VFS_NAME))==SQLITE_OK ){
    /** THE UPPER PAGER (usual pager for DB) IS NOT NEEDED. CEVFS WILL USE ITS OWN (LOWER) PAGER. */
    rc = sqlite3_exec(db, "PRAGMA journal_mode=OFF;", NULL, 0, 0);

    /** ADJUST UPPER PAGER SIZE USING PRAGMA. Set CEVFS (lower) page size in URI. */
    //rc = sqlite3_exec(db, "PRAGMA page_size=2048", NULL, 0, 0); // upper level page size

    if( (rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS dict (key int, entry text, definition text);" \
      "CREATE INDEX IF NOT EXISTS ix_key ON dict(key);" \
      "CREATE INDEX IF NOT EXISTS ix_dict ON dict(entry);", NULL, 0, &zErrMsg))==SQLITE_OK
    ){
      char buf[256];
      if( (rc = sqlite3_exec(db, "BEGIN TRANSACTION", NULL, 0, 0)) == SQLITE_OK ){
        for (int i=0; rc==SQLITE_OK && i<100000; i++) {
          long key = random();
          snprintf(buf, sizeof(buf), "insert into dict values('%ld', 'This is a test #%03d', 'Trying to compress this string #%03d')", key, i, i);
          rc = sqlite3_exec(db, buf, NULL, 0, &zErrMsg);
        }
        if( rc == SQLITE_OK ){
          rc = sqlite3_exec(db, "COMMIT", NULL, 0, 0);
        }else{
          rc = sqlite3_exec(db, "ROLLBACK TRANSACTION", NULL, 0, 0);
        }
      }
    }

    if( sqlite3_errcode(db) == CEVFS_ERROR ){
      switch( sqlite3_extended_errcode(db) ){
        case CEVFS_ERROR_PAGE_SIZE_TOO_SMALL:
          break;
        case CEVFS_ERROR_MALFORMED_KEY:
          break;
        case CEVFS_ERROR_EXT_VERSION_TOO_OLD:
          break;
        case CEVFS_ERROR_VFS_ALREADY_EXISTS:
          break;
        case CEVFS_ERROR_COMPRESSION_FAILED:
          break;
        case CEVFS_ERROR_DECOMPRESSION_FAILED:
          break;
        case CEVFS_ERROR_ENCRYPTION_FAILED:
          break;
        case CEVFS_ERROR_DECRYPTION_FAILED:
          break;
      }
    }

    if( rc!=SQLITE_OK ) sqlite3_close(db);
    else rc = sqlite3_close(db);
  }
  return rc;
}

int testRead(char *zErrMsg){
  sqlite3 *db;
  int rc;
  if( (rc = sqlite3_open_v2(dbFile, &db, SQLITE_OPEN_READONLY, VFS_NAME))==SQLITE_OK ){
    if( (rc = sqlite3_exec(db, "select * from dict where key>1000000000 and key<=1020000000 order by entry;", callback, 0, &zErrMsg))==SQLITE_OK){
    }
  }
  if( rc==CEVFS_ERROR ){
    if( sqlite3_extended_errcode(db) == CEVFS_ERROR_EXT_VERSION_TOO_OLD ){
      zErrMsg = "You need a newer version of CEVFS";
    }
  }
  sqlite3_close(db);
  return rc;
}

/*
** MAIN
*/
int main(int argc, const char * argv[]) {
  char *zErrMsg = 0;
  int rc;

  time_t t;
  srand((unsigned)time(&t));

#if SQL_DEBUG_OUTPUT
  FILE *f = stdout;
#else
  FILE *f = fopen("/dev/null", "w");
#endif

  // This context will be passed to xAutoDetect and the functions defined within.
  struct context ctx;

  // Sample encryption key
  char keyBytes[4][8] = {
    { 0x8F, 0x22, 0xC9, 0xBA, 0xFE, 0x11, 0x3C, 0xF0 },
    { 0xAF, 0x66, 0x22, 0xC5, 0x73, 0x2E, 0x84, 0xBD },
    { 0x31, 0x16, 0x19, 0x83, 0x8A, 0x6F, 0xAA, 0x24 },
    { 0x71, 0xD8, 0x6C, 0x32, 0x99, 0xCA, 0x29, 0x2A }
  };

  ctx.pKey   = keyBytes;            // 32-bit encryption hex key
  ctx.nKeySz = kCCKeySizeAES256;    // key size in bytes
  ctx.nIvSz  = kCCBlockSizeAES128;  // size of IV in bytes

  if( (rc = cevfs_create_vfs(VFS_NAME, NULL, &ctx, cevfsAutoDetect, 0))==SQLITE_OK ){
    rc = SQLITE_OK;

#if SQL_TEST_WRITE
    rc = testWrite(zErrMsg);
#endif

#if SQL_TEST_READ
    if( rc==SQLITE_OK ){
      rc = testRead(zErrMsg);
    }
#endif
  }

  if( rc != SQLITE_OK ){
    if( zErrMsg ) fprintf(stderr, "SQL error: %s\n", zErrMsg);
    else fprintf(stderr, "SQL error: %d\n", rc);
    sqlite3_free(zErrMsg);
  }else{
    fputs("Done\n", stdout);
  }
  fclose(f);
  cevfs_destroy_vfs(VFS_NAME);
  return 0;
}
