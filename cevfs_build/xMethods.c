//
//  xMethods.c
//  cevfs_build
//
//  Created by Ryan Homer on 26/6/2016.
//  Copyright © 2016 Murage Inc. All rights reserved.
//

#include <stdlib.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

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

int cevfsDecrypt(void *pDecryptCtx, const void *pDataIn, size_t nDataInSize, const void *pIvIn, void *pDataOut, size_t nDataBufferSizeOut, size_t *nDataSizeOut) {
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
  return true;
}
