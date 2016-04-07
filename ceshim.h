//
//  ceshim.h
//  sqlite
//
//  Created by Ryan Homer on 5/2/2016.
//  Copyright © 2016 Murage Inc. All rights reserved.
//

#ifndef ceshim_h
#define ceshim_h

#define CESHIM_ERROR                       111
#define CESHIM_ERROR_PAGE_SIZE_TOO_SMALL   (CESHIM_ERROR | (1<<8))
#define CESHIM_ERROR_MALFORMED_KEY         (CESHIM_ERROR | (2<<8))
#define CESHIM_ERROR_EXT_VERSION_TOO_OLD   (CESHIM_ERROR | (3<<8))

int ceshim_register(
  const char *zName,                /* Name of the newly constructed VFS */
  const char *zParent,              /* Name of the underlying VFS. NULL to use default. */
  void *pCtx,                       /* Context pointer to be passed to compress functions */
  int (*xCompressBound)(void *pCtx, int nSrc),
  int (*xCompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xUncompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc)
);

int ceshim_unregister(const char *zName);

#endif /* ceshim_h */
