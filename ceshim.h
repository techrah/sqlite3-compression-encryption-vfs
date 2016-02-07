//
//  ceshim.h
//  sqlite
//
//  Created by Ryan Homer on 5/2/2016.
//  Copyright © 2016 Murage Inc. All rights reserved.
//

#ifndef ceshim_h
#define ceshim_h

int ceshim_register(
  const char *zName,                /* Name of the newly constructed VFS */
  const char *zParent,              /* Name of the underlying VFS */
  void *pCtx,
  int (*xCompressBound)(void *, int nSrc),
  int (*xCompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xUncompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xOut)(const char*,void*),   /* Output routine. */
  void *pOutArg,                    /* 2nd argument to xOut.  ex: stderr */
  int makeDefault                   /* True to make the new VFS the default */
);

#endif /* ceshim_h */
