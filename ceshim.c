/*
 Compression & Encryption Shim VFS
*/
#ifndef SQLITE_AMALGAMATION
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"
#include "sqliteInt.h"
#include "pager.h"
#include "btreeInt.h"
#endif
#include <sys/stat.h>
#include <zlib.h>
#include "ceshim.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

// Size of standard Sqlite3 pager header
#define CESHIM_DB_HEADER1_SZ        100
// Size of ceshim-specific pager header
#define CESHIM_DB_HEADER2_SZ        100
#define CESHIM_DB_HEADER1_OFST      000
#define CESHIM_DB_HEADER2_OFST      CESHIM_DB_HEADER1_OFST+CESHIM_DB_HEADER1_SZ
// Offset to master map table
#define CESHIM_DB_MMTBL_OFST        CESHIM_DB_HEADER2_OFST+CESHIM_DB_HEADER2_SZ
#define CESHIM_DB_HEADER_SIZE       (CESHIM_DB_HEADER1_SZ + CESHIM_DB_HEADER2_SZ)

#define CESHIM_FILE_SCHEMA_NO         1
#define CESHIM_FIRST_MAPPED_PAGE      3

#ifdef SQLITE_DEBUG
#define CESHIM_PRINTF(a,b,...) ceshim_printf(a,b,##__VA_ARGS__)
#else
#define CESHIM_PRINTF(a,b,...)
#endif

typedef u16 CeshimCmpSize;
typedef u16 CeshimCmpOfst;

/*
** The header string that appears at the beginning of every
** SQLite database.
*/
#ifndef SQLITE_AMALGAMATION
static const char zMagicHeader[] = SQLITE_FILE_HEADER;
#endif

/*
** Keeps track of data we need to persist for the pager.
** This will be stored uncompressed at offset 100-199.
*/
typedef struct ceshim_header ceshim_header;
struct ceshim_header {
  u8 schema;                            // 01 file schema version number
  Pgno currPgno;                        // 04 curr lower pager pgno being filled
  CeshimCmpOfst currPageOfst;           // 02 curr offset for next compressed page
  u16 pgMapCnt;                         // 02 num elements of last page map
  u32 uppPgSz;                          // 04 Upper pager page size. Could be different from lower pager's
  Pgno uppPageFile;                     // 04 max pgno in upper pager, used to report filesize
  u16 mmTblMaxCnt;                      // 02 max entries avail for master map table, computed when table is loaded
  u16 mmTblCurrCnt;                     // 02 curr total elements used in master map table
  unsigned char reserved[79];           // 79 pad structure to 100 bytes
};

/*
** Page 1, bytes from offset CESHIM_DB_HEADER2_OFST to end of page, will have a master map for coordinating
** all the other mapping tables. If table becomes full, perhaps a larger pagesize will help.
** This table could be extended at the expense of the size of the first page map table.
** After experimenting with various database sizes, this will be revised.
*/
typedef struct CeshimMMTblEntry CeshimMMTblEntry;
struct __attribute__ ((__packed__)) CeshimMMTblEntry {
  Pgno lwrPgno;                        // 04 lower pager pgno where actual page map data is stored
};

/*
** Each time we read a page, it'll be associated with a CeshimMemPage
** to store temporary in-memory data that belongs to this page.
*/
typedef struct CeshimMemPage CeshimMemPage;
struct CeshimMemPage {
  DbPage *pDbPage;                     /* Pager page handle */
  Pgno pgno;                           /* The pgno to which this belongs */
  u16 dbHdrOffset;                     /* Offset to the beginning of the header */
  u16 pgHdrOffset;                     /* Offset to the beginning of the data */
  u8 *aData;                           /* Pointer to disk image of the page data */
};

/*
** Mapping table for uncompressed to compressed content.
** The table is stored on page 2 at offset 0.
** The maximum size of table depends on the pager page size.
** If that is not enough, multiple tables will be used.
** As each new table is created, it is stored on the next available page.
*/
typedef struct ceshim_map_entry ceshim_map_entry;
struct __attribute__ ((__packed__)) ceshim_map_entry {
  Pgno lwrPgno;                     // 04 mapped lower pager pgno
  CeshimCmpSize cmprSz;             // 02 size of compressed page
  CeshimCmpOfst cmprOfst;           // 02 lower page offset for compressed page
};

/*
** An instance of this structure is attached to each ceshim VFS to
** provide auxiliary non-persisted information.
*/
typedef struct ceshim_file ceshim_file;
typedef struct ceshim_info ceshim_info;
struct ceshim_info {
  sqlite3_vfs *pRootVfs;              // The underlying real VFS
  const char *zVfsName;               // Name of this VFS
  sqlite3_vfs *pCeshimVfs;            // Pointer back to the ceshim VFS
  ceshim_file *pFile;                 // Pointer back to the ceshim_file representing the dest. db.
  int cerod_activated;                // if extension is enabled, make sure read only
  char *zKey;                         // Encryption key blob for each file opened with this VFS instance
  int key_sz;                         // Key size in bytes
  int iv_sz;                          // IV blob size in bytes

  // Pointers to custom compress functions implemented by the user
  void *pCtx;
  int (*xCompressBound)(void *pCtx, int nSrc);
  int (*xCompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc);
  int (*xUncompress)(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc);
};

/*
** The sqlite3_file object for the shim.
*/
struct ceshim_file {
  sqlite3_file base;                  // Base class.  Must be first
  sqlite3_file *pReal;                // The real underlying file
  ceshim_info *pInfo;                 // Custom info for this file
  const char *zFName;                 // Base name of the file
  char *zUppJournalPath;              // Path to redirect upper journal
  unsigned char zDbHeader[100];       // Sqlite3 DB header
  ceshim_header ceshimHeader;         // Ceshim header with page mapping data
  char *zKey;                         // Encryption key blob for this file

  // map
  CeshimMMTblEntry *mmTbl;            // The master mapping table
  u16 mmTblCurrIx;                    // Index of the current page map in mmTbl
  ceshim_map_entry *pPgMap;           // The current page map
  ceshim_map_entry *pBigEndianPgMap;  // Used for converting integers to big-endian when saving
  u16 pgMapMaxCnt;                    // Max entries for a page map, based on page size
  u16 pgMapSz;                        // Size in bytes for the page map allocation
  u32 nBytesPerPgMap;                 // Performance optimization premultiplication store

  // bools
  u8 bPgMapDirty:1;                   // Curr page map needs to be persisted
  u8 bReadOnly:1;                     // True when db was open for read-only

  // pager
  CeshimMemPage *pPage1;              // Page 1 of the pager
  Pager *pPager;                      // Pager for I/O with compressed/encrypted file
  Pgno lwrPageFile;                   // max pgno in lower pager, used to update pager header
  u32 pageSize;                       // Page size of the lower pager
  u32 usableSize;                     // Number of usable bytes on each page
  u8 nTransactions;                   // Number of open transactions on the pager
};

/*
** Method declarations for ceshim_file.
*/
static int ceshimClose(sqlite3_file*);
static int ceshimRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int ceshimWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64);
static int ceshimTruncate(sqlite3_file*, sqlite3_int64 size);
static int ceshimSync(sqlite3_file*, int flags);
static int ceshimFileSize(sqlite3_file*, sqlite3_int64 *pSize);
static int ceshimLock(sqlite3_file*, int);
static int ceshimUnlock(sqlite3_file*, int);
static int ceshimCheckReservedLock(sqlite3_file*, int *);
static int ceshimFileControl(sqlite3_file*, int op, void *pArg);
static int ceshimSectorSize(sqlite3_file*);
static int ceshimDeviceCharacteristics(sqlite3_file*);
static int ceshimShmLock(sqlite3_file*,int,int,int);
static int ceshimShmMap(sqlite3_file*,int,int,int, void volatile **);
static void ceshimShmBarrier(sqlite3_file*);
static int ceshimShmUnmap(sqlite3_file*,int);

/*
** Method declarations for ceshim_vfs.
*/
static int ceshimOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);
static int ceshimDelete(sqlite3_vfs*, const char *zName, int syncDir);
static int ceshimAccess(sqlite3_vfs*, const char *zName, int flags, int *);
static int ceshimFullPathname(sqlite3_vfs*, const char *zName, int, char *);
static void *ceshimDlOpen(sqlite3_vfs*, const char *zFilename);
static void ceshimDlError(sqlite3_vfs*, int nByte, char *zErrMsg);
static void (*ceshimDlSym(sqlite3_vfs*,void*, const char *zSymbol))(void);
static void ceshimDlClose(sqlite3_vfs*, void*);
static int ceshimRandomness(sqlite3_vfs*, int nByte, char *zOut);
static int ceshimSleep(sqlite3_vfs*, int microseconds);
static int ceshimCurrentTime(sqlite3_vfs*, double*);
static int ceshimGetLastError(sqlite3_vfs*, int, char*);
static int ceshimCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);

/*
** Forward declarations
*/
static CeshimMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno);
static int ceshimNewDatabase(ceshim_file *pFile);
static int ceshimWriteUncompressed(ceshim_file *, Pgno, CeshimCmpOfst, const void *zBuf, int iAmt);
static int ceshimReadUncompressed(ceshim_file *, Pgno, CeshimCmpOfst, void *zBuf, int iAmt);
static int ceshimSaveHeader(ceshim_file *p);
static int ceshimLoadHeader(ceshim_file *p);

/*
** Return a pointer to the tail of the pathname.  Examples:
**
**     /home/drh/xyzzy.txt -> xyzzy.txt
**     xyzzy.txt           -> xyzzy.txt
*/
static const char *fileTail(const char *z){
  int i;
  if( z==0 ) return 0;
  i = (int)strlen(z)-1;
  while( i>0 && z[i-1]!='/' ){ i--; }
  return &z[i];
}

/*
** Map the upper pager's journal file onto a different name.
** findCreateFileMode() in os_unix.c requires journal file to be in same directory
** and not have additional '-' in name. We'll just append "btree" to distinguish it from ours.
** Note: everything after the '-' must be alphanumeric only. No punctuation allowed
** or an assertion will be triggered in debug mode.
*/
static char * ceshimMapPath(ceshim_file *pFile, const char *zName, bool *bMustRelease){
  static const char *zTail = "btree";
  if (bMustRelease) *bMustRelease = false;
  if( strstr(zName, "-journal")==0 ) return zName;
  char *zUppJournalPath = pFile ? pFile->zUppJournalPath : NULL;
  if( zUppJournalPath == NULL ){
    zUppJournalPath = sqlite3_malloc((int)(strlen(zName)+strlen(zTail))+1);
    *zUppJournalPath = '\0';
    strcat(zUppJournalPath, zName);
    strcat(zUppJournalPath, zTail);
    if(pFile)
      pFile->zUppJournalPath = zUppJournalPath;
    else
      if (bMustRelease) *bMustRelease = true;
  }
  return zUppJournalPath;
}

/*
** Send trace output defined by zFormat and subsequent arguments.
*/
static void ceshim_printf(
  ceshim_info *pInfo,
  const char *zFormat,
  ...
){
  va_list ap;
  char *zMsg;
  va_start(ap, zFormat);
  zMsg = sqlite3_vmprintf(zFormat, ap);
  va_end(ap);
  fputs(zMsg, stdout);
  sqlite3_free(zMsg);
}

/*
** Convert value rc into a string and print it using zFormat.  zFormat
** should have exactly one %s
*/
static void ceshim_print_errcode(
  ceshim_info *pInfo,
  const char *zFormat,
  int rc
){
  char zBuf[50];
  char *zVal;
  switch( rc ){
    case SQLITE_OK:         zVal = "SQLITE_OK";          break;
    case SQLITE_ERROR:      zVal = "SQLITE_ERROR";       break;
    case SQLITE_PERM:       zVal = "SQLITE_PERM";        break;
    case SQLITE_ABORT:      zVal = "SQLITE_ABORT";       break;
    case SQLITE_BUSY:       zVal = "SQLITE_BUSY";        break;
    case SQLITE_NOMEM:      zVal = "SQLITE_NOMEM";       break;
    case SQLITE_READONLY:   zVal = "SQLITE_READONLY";    break;
    case SQLITE_INTERRUPT:  zVal = "SQLITE_INTERRUPT";   break;
    case SQLITE_IOERR:      zVal = "SQLITE_IOERR";       break;
    case SQLITE_CORRUPT:    zVal = "SQLITE_CORRUPT";     break;
    case SQLITE_FULL:       zVal = "SQLITE_FULL";        break;
    case SQLITE_CANTOPEN:   zVal = "SQLITE_CANTOPEN";    break;
    case SQLITE_PROTOCOL:   zVal = "SQLITE_PROTOCOL";    break;
    case SQLITE_EMPTY:      zVal = "SQLITE_EMPTY";       break;
    case SQLITE_SCHEMA:     zVal = "SQLITE_SCHEMA";      break;
    case SQLITE_CONSTRAINT: zVal = "SQLITE_CONSTRAINT";  break;
    case SQLITE_MISMATCH:   zVal = "SQLITE_MISMATCH";    break;
    case SQLITE_MISUSE:     zVal = "SQLITE_MISUSE";      break;
    case SQLITE_NOLFS:      zVal = "SQLITE_NOLFS";       break;
    case SQLITE_IOERR_READ:         zVal = "SQLITE_IOERR_READ";         break;
    case SQLITE_IOERR_SHORT_READ:   zVal = "SQLITE_IOERR_SHORT_READ";   break;
    case SQLITE_IOERR_WRITE:        zVal = "SQLITE_IOERR_WRITE";        break;
    case SQLITE_IOERR_FSYNC:        zVal = "SQLITE_IOERR_FSYNC";        break;
    case SQLITE_IOERR_DIR_FSYNC:    zVal = "SQLITE_IOERR_DIR_FSYNC";    break;
    case SQLITE_IOERR_TRUNCATE:     zVal = "SQLITE_IOERR_TRUNCATE";     break;
    case SQLITE_IOERR_FSTAT:        zVal = "SQLITE_IOERR_FSTAT";        break;
    case SQLITE_IOERR_UNLOCK:       zVal = "SQLITE_IOERR_UNLOCK";       break;
    case SQLITE_IOERR_RDLOCK:       zVal = "SQLITE_IOERR_RDLOCK";       break;
    case SQLITE_IOERR_DELETE:       zVal = "SQLITE_IOERR_DELETE";       break;
    case SQLITE_IOERR_BLOCKED:      zVal = "SQLITE_IOERR_BLOCKED";      break;
    case SQLITE_IOERR_NOMEM:        zVal = "SQLITE_IOERR_NOMEM";        break;
    case SQLITE_IOERR_ACCESS:       zVal = "SQLITE_IOERR_ACCESS";       break;
    case SQLITE_IOERR_CHECKRESERVEDLOCK:
                               zVal = "SQLITE_IOERR_CHECKRESERVEDLOCK"; break;
    case SQLITE_IOERR_LOCK:         zVal = "SQLITE_IOERR_LOCK";         break;
    case SQLITE_IOERR_CLOSE:        zVal = "SQLITE_IOERR_CLOSE";        break;
    case SQLITE_IOERR_DIR_CLOSE:    zVal = "SQLITE_IOERR_DIR_CLOSE";    break;
    case SQLITE_IOERR_SHMOPEN:      zVal = "SQLITE_IOERR_SHMOPEN";      break;
    case SQLITE_IOERR_SHMSIZE:      zVal = "SQLITE_IOERR_SHMSIZE";      break;
    case SQLITE_IOERR_SHMLOCK:      zVal = "SQLITE_IOERR_SHMLOCK";      break;
    case SQLITE_IOERR_SHMMAP:       zVal = "SQLITE_IOERR_SHMMAP";       break;
    case SQLITE_IOERR_SEEK:         zVal = "SQLITE_IOERR_SEEK";         break;
    case SQLITE_IOERR_GETTEMPPATH:  zVal = "SQLITE_IOERR_GETTEMPPATH";  break;
    case SQLITE_IOERR_CONVPATH:     zVal = "SQLITE_IOERR_CONVPATH";     break;
    case SQLITE_READONLY_DBMOVED:   zVal = "SQLITE_READONLY_DBMOVED";   break;
    case SQLITE_LOCKED_SHAREDCACHE: zVal = "SQLITE_LOCKED_SHAREDCACHE"; break;
    case SQLITE_BUSY_RECOVERY:      zVal = "SQLITE_BUSY_RECOVERY";      break;
    case SQLITE_CANTOPEN_NOTEMPDIR: zVal = "SQLITE_CANTOPEN_NOTEMPDIR"; break;
    default: {
       sqlite3_snprintf(sizeof(zBuf), zBuf, "%d", rc);
       zVal = zBuf;
       break;
    }
  }
  CESHIM_PRINTF(pInfo, zFormat, zVal);
}

/*
** Append to a buffer.
*/
static void strappend(char *z, int *pI, const char *zAppend){
  int i = *pI;
  while( zAppend[0] ){ z[i++] = *(zAppend++); }
  z[i] = 0;
  *pI = i;
}

static int ceshimReadUncompressed(
  ceshim_file *p,
  Pgno pgno,
  CeshimCmpOfst offset,
  void *zBuf,
  int iAmt
){
  int rc;
  DbPage *pPage;
  if( (rc = sqlite3PagerGet(p->pPager, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    memcpy(zBuf, data+offset, iAmt);
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static void ceshimReleasePage1(ceshim_file *p){
  ceshim_info *pInfo = p->pInfo;
  if( p->pPage1 ){
    sqlite3PagerUnref(p->pPage1->pDbPage);
    p->pPage1 = NULL;
  }
}

/*
** Create master mapping table.
** This table will point to the actual upper-to-lower page maps.
** Its size depends on the page size of the lower pager.
*/
static int ceshimCreateMMTbl(ceshim_file *p, int *memSzOut){
  ceshim_info *pInfo = p->pInfo;
  u16 maxSz = p->pageSize - CESHIM_DB_HEADER_SIZE;
  u16 maxEntries = maxSz / sizeof(CeshimMMTblEntry);

  // At this point, header may already be loaded from persistent storage
  // so be careful modifying header values
  p->ceshimHeader.mmTblMaxCnt = maxEntries;
  p->mmTblCurrIx = -1; // u16, so results in some large number to mean "not defined"

  // allocate
  int memSz = maxEntries*sizeof(CeshimMMTblEntry);
  if( !(p->mmTbl = sqlite3_malloc(memSz)) ) return SQLITE_NOMEM;

  // out param
  if( memSzOut ) *memSzOut = memSz;
  return SQLITE_OK;
}

static int ceshimSavePagemapData(ceshim_file *p){
  int rc = SQLITE_OK;
  ceshim_info *pInfo = p->pInfo;
  if( p->bPgMapDirty ){
    Pgno pgno = p->mmTbl[p->mmTblCurrIx].lwrPgno;
    rc = ceshimWriteUncompressed(p, pgno, 0, p->pBigEndianPgMap, p->pgMapSz);
    if( rc==SQLITE_OK ) p->bPgMapDirty = 0;
  }
  return rc;
}

static int ceshimSaveMMTbl(ceshim_file *p){
  int rc;
  ceshim_info *pInfo = p->pInfo;
  assert( p->bReadOnly==0 );
  ceshim_header *header = &p->ceshimHeader;
  int memSz = header->mmTblMaxCnt*sizeof(CeshimMMTblEntry);
  CeshimMMTblEntry *buf = sqlite3_malloc(memSz);
  if( buf ){
    for(u16 i=0; i<header->mmTblCurrCnt; i++){
      put2byte((u8 *)&buf[i].lwrPgno, p->mmTbl[i].lwrPgno);
    }
    if( (rc = ceshimWriteUncompressed(p, 1, CESHIM_DB_MMTBL_OFST, buf, memSz))==SQLITE_OK){
      sqlite3_free(buf);
      rc = ceshimSavePagemapData(p);
    }
  }else rc = SQLITE_NOMEM;
  return rc;
}

static int ceshimLoadPagemapData(ceshim_file *p, u16 ix){
  int rc;
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &p->ceshimHeader;
  assert( p->bPgMapDirty==0 );
  assert( ix != p->mmTblCurrIx ); // mmTblCurrIx initially large number to mean no entries yet
  Pgno pgno = p->mmTbl[ix].lwrPgno;
  rc = ceshimReadUncompressed(p, pgno, 0, p->pBigEndianPgMap, p->pgMapSz);
  if( rc==SQLITE_OK ){
    u16 maxCnt = ix==header->mmTblCurrCnt-1 ? header->pgMapCnt : p->pgMapMaxCnt;
    for(u16 i = 0; i<maxCnt; i++){
      p->pPgMap[i].lwrPgno = get4byte((u8 *)&p->pBigEndianPgMap[i].lwrPgno);
      p->pPgMap[i].cmprSz = get2byte((u8 *)&p->pBigEndianPgMap[i].cmprSz);
      p->pPgMap[i].cmprOfst = get2byte((u8 *)&p->pBigEndianPgMap[i].cmprOfst);
    }
    p->mmTblCurrIx = ix;
  }
  return rc;
}

static int ceshimLoadMMTbl(ceshim_file *p){
  int rc;
  int memSz;
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &p->ceshimHeader;
  assert( p->mmTbl==NULL );

  // Header must have already been loaded
  assert( header->mmTblCurrCnt>0 );

  if( (rc = ceshimCreateMMTbl(p, &memSz))==SQLITE_OK ){
    CeshimMMTblEntry *buf = sqlite3_malloc(memSz);
    if( buf ){
      if( (rc = ceshimReadUncompressed(p, 1, CESHIM_DB_MMTBL_OFST, buf, memSz))==SQLITE_OK){
        for(u16 i=0; i<header->mmTblCurrCnt; i++){
          p->mmTbl[i].lwrPgno = get2byte((u8 *)&buf[i].lwrPgno);
        }
        sqlite3_free(buf);
      }
   }
  }else rc = SQLITE_NOMEM;
  return rc;
}

static int ceshimPagerLock(ceshim_file *p){
  ceshim_info *pInfo = p->pInfo;
  int rc;
  assert( p->pPage1==0 );
  if( (rc = sqlite3PagerSharedLock(p->pPager))==SQLITE_OK ){
    DbPage *pDbPage1;
    if( (rc = sqlite3PagerGet(p->pPager, 1, &pDbPage1, 0))==SQLITE_OK ){
      p->pPage1 = memPageFromDbPage(pDbPage1, 1);
      int nPageFile = 0;
      sqlite3PagerPagecount(p->pPager, &nPageFile);

      // calc max entries for each page map based on page size
      p->pgMapMaxCnt = p->pageSize / sizeof(ceshim_map_entry);
      p->pgMapSz = p->pgMapMaxCnt * sizeof(ceshim_map_entry);

      // Optimization: Do this multiplication and store it for later use.
      p->nBytesPerPgMap = p->pgMapMaxCnt * p->ceshimHeader.uppPgSz;

      /* Allocate space for a single page map.
         Only one page map will be in memory at a time. */
      p->pPgMap = sqlite3_malloc(p->pgMapSz);
      p->pBigEndianPgMap = sqlite3_malloc(p->pgMapSz);
      if( p->pPgMap && p->pBigEndianPgMap ){
        memset((void *)p->pPgMap, 0, p->pgMapSz);
        memset((void *)p->pBigEndianPgMap, 0, p->pgMapSz);
        if( nPageFile==0 ){
          /* We will be creating a new database so set up some data that is
             needed right away that would be too late to do in ceshimNewDatabase(). */
          if( (rc = ceshimCreateMMTbl(p, NULL))==SQLITE_OK ){
            p->mmTbl[0].lwrPgno = 2;
            p->ceshimHeader.mmTblCurrCnt = 1;
          }
        }else{
          // restore some data
          rc = ceshimLoadHeader(p);
          if( rc==SQLITE_OK && p->ceshimHeader.schema > CESHIM_FILE_SCHEMA_NO ){
            // The file schema# is larger than this version can handle.
            // A newer version is needed to read this file.
            rc = CESHIM_ERROR_EXT_VERSION_TOO_OLD;
          }
          if( rc==SQLITE_OK ) rc = ceshimLoadMMTbl(p);
          if( rc==SQLITE_OK ) rc = ceshimLoadPagemapData(p, 0);
        }
        /* reminder: do not call sqlite3PagerUnref(pDbPage1) here as this will
           cause pager state to reset to PAGER_OPEN which is not desirable for writing to pager. */
      }else rc = SQLITE_NOMEM;
    }
  }
  return rc;
}

static int ceshimPagerWrite(ceshim_file *p, PgHdr *pPg){
  int rc = SQLITE_OK;
  if( p->nTransactions == 0 ){
    if( (rc = sqlite3PagerBegin(p->pPager, 0, 1))==SQLITE_OK ){
      p->nTransactions++;
      if( p->lwrPageFile==0 ){
        rc = ceshimNewDatabase(p);
      }
    }
  }
  if( rc==SQLITE_OK ) return sqlite3PagerWrite(pPg);
  return rc;
}

static int ceshimWriteUncompressed(
  ceshim_file *pFile,
  Pgno pgno,
  CeshimCmpOfst offset,
  const void *zBuf,
  int iAmt
){
  int rc;
  DbPage *pPage = NULL;
  if( (rc = sqlite3PagerGet(pFile->pPager, pgno, &pPage, 0)) == SQLITE_OK ){
    void *data = sqlite3PagerGetData(pPage);
    if( (rc = ceshimPagerWrite(pFile, pPage)) == SQLITE_OK ){
      memcpy(data+offset, zBuf, iAmt);
    }
    sqlite3PagerUnref(pPage);
  }
  return rc;
}

static int ceshimSaveHeader(ceshim_file *p){
  ceshim_info *pInfo = p->pInfo;
  assert( p->bReadOnly==0 );
  ceshim_header *header = &p->ceshimHeader;
  u8 buf[CESHIM_DB_HEADER2_SZ];
  memcpy(buf, &header->schema, 1);
  put4byte(buf+1, header->currPgno);
  put2byte(buf+5, header->currPageOfst);
  put2byte(buf+7, header->pgMapCnt);
  put4byte(buf+9, header->uppPgSz);
  put4byte(buf+13, header->uppPageFile);
  put2byte(buf+17, header->mmTblMaxCnt);
  put2byte(buf+19, header->mmTblCurrCnt);
  memset(buf+21, 0, 79);
  return ceshimWriteUncompressed(p, 1, CESHIM_DB_HEADER2_OFST, buf, CESHIM_DB_HEADER2_SZ);
}

static int ceshimLoadHeader(ceshim_file *p){
  ceshim_header *header = &p->ceshimHeader;
  u8 buf[CESHIM_DB_HEADER2_SZ];
  int rc;
  if( (rc = ceshimReadUncompressed(p, 1, CESHIM_DB_HEADER2_OFST, buf, CESHIM_DB_HEADER2_SZ))==SQLITE_OK ){
    header->schema = buf[0];
    header->currPgno = get4byte(buf+1);
    header->currPageOfst = get2byte(buf+5);
    header->pgMapCnt = get2byte(buf+7);
    header->uppPgSz = get4byte(buf+9);
    header->uppPageFile = get4byte(buf+13);
    header->mmTblMaxCnt = get2byte(buf+17);
    header->mmTblCurrCnt = get2byte(buf+19);
  }
  return rc;
}

static CeshimMemPage *memPageFromDbPage(DbPage *pDbPage, Pgno mappedPgno){
  CeshimMemPage* pPg = (CeshimMemPage *)sqlite3PagerGetExtra(pDbPage);
  if(mappedPgno != pPg->pgno  ){
    pPg->pgno = mappedPgno;
    pPg->pDbPage = pDbPage;
    pPg->dbHdrOffset = mappedPgno==1 ? CESHIM_DB_HEADER_SIZE : 0;
    pPg->pgHdrOffset = 0; // Not used anymore
    pPg->pDbPage->pgno = mappedPgno; // pager uses this to determine pager size
    pPg->aData = sqlite3PagerGetData(pDbPage);
  }
  return pPg;
}

static int ceshimNewDatabase(ceshim_file *pFile){
  CeshimMemPage *pP1;
  unsigned char *data;
  int rc;
  ceshim_info *pInfo = pFile->pInfo;

  pP1 = pFile->pPage1;
  data = pP1->aData;
  if( (rc = ceshimPagerWrite(pFile, pP1->pDbPage))==SQLITE_OK ){
    // since we are using a secondary pager, set up a proper pager header (see btree.c:1898)
    memcpy(data, zMagicHeader, sizeof(zMagicHeader));
    assert( sizeof(zMagicHeader)==16 );
    data[16] = (u8)((pFile->pageSize>>8)&0xff);
    data[17] = (u8)((pFile->pageSize>>16)&0xff);
    data[18] = 1;
    data[19] = 1;
    assert( pFile->usableSize<=pFile->pageSize && pFile->usableSize+255>=pFile->pageSize);
    data[20] = (u8)(pFile->pageSize - pFile->usableSize);
    data[21] = 64;
    data[22] = 32;
    data[23] = 32;
    memset(&data[24], 0, 100-24);
    data[31] = 1; // 28-31 size of the database file in pages
  }
  return rc;
}

/*
** Switch to a specific page map based on pager offset,
** saving the current page map if needed.
** @returns index# of page map switched to.
*/
static u16 ceshimSwitchPageMap(ceshim_file *p, sqlite_int64 iUppOfst){
  int rc = SQLITE_ERROR;
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &p->ceshimHeader;
  u16 ix = 0;

  /*
    Calculate map index based on upper pager offset.
    Check last entry first as an optimization in case we are writing.
    Perhaps we can do this check only when we are writing, skip for read-only.
  */
  ix = iUppOfst >= (p->nBytesPerPgMap * header->mmTblCurrCnt)
    ? header->mmTblCurrCnt-1
    : (u16)(iUppOfst / p->nBytesPerPgMap);
  if( ix<header->mmTblCurrCnt ) rc=SQLITE_OK;

  // switch
  if( rc==SQLITE_OK && ix != p->mmTblCurrIx ){
    CESHIM_PRINTF(pInfo, "Switching to map #%u for offset %lld\n", (unsigned)ix, iUppOfst);
    // save
    if( (rc = ceshimSavePagemapData(p))==SQLITE_OK ){
      // reset
      memset(p->pPgMap, 0, p->pgMapSz);
      //load
      rc = ceshimLoadPagemapData(p, ix);
      if( rc==SQLITE_OK ) p->mmTblCurrIx = ix;
    }
  }
  return ix;
}

static int ceshimPageMapGet(
  ceshim_file *pFile,
  sqlite_uint64 uSrcOfst,
  Pgno *outUppPgno,
  Pgno *outLwrPgno,
  CeshimCmpOfst *outCmpOfst,
  CeshimCmpSize *outCmpSz,
  u16 *outIx
){
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pFile->ceshimHeader;
  if( outUppPgno ) *outUppPgno = (Pgno)(uSrcOfst/header->uppPgSz+1);
  int currPgMapNo = ceshimSwitchPageMap(pFile, uSrcOfst);
  if( pFile->pPgMap ){
    // determine max elements based on if last page map is currently in memory
    u16 maxCnt = pFile->mmTblCurrIx==header->mmTblCurrCnt-1 ? header->pgMapCnt : pFile->pgMapMaxCnt;
#if 1
    u16 pgMapIx = (u16)(uSrcOfst/pFile->nBytesPerPgMap);
    int ix = uSrcOfst % pFile->nBytesPerPgMap / header->uppPgSz;
    if(
      ix<maxCnt                 // if we go beyond maxCnt, entry doesn't exist yet
      && pgMapIx==currPgMapNo   // if pgMap not yet created, entry doesn't exist yet
    ){
      if( outLwrPgno ) *outLwrPgno = pFile->pPgMap[ix].lwrPgno;
      if( outCmpSz ) *outCmpSz = pFile->pPgMap[ix].cmprSz;
      if( outCmpOfst ) *outCmpOfst = pFile->pPgMap[ix].cmprOfst;
      if( outIx ) *outIx = ix;
      return SQLITE_OK;
    }
#else
    for( int i=0; i<maxCnt; i++ ){
      if(
         pInfo->pPgMap[i].uppOfst <= uSrcOfst
         && uSrcOfst < pInfo->pPgMap[i].uppOfst+header->uppPgSz
      ){
        if( outLwrPgno ) *outLwrPgno = pInfo->pPgMap[i].lwrPgno;
        if( outCmpSz ) *outCmpSz = pInfo->pPgMap[i].cmprSz;
        if( outCmpOfst ) *outCmpOfst = pInfo->pPgMap[i].cmprOfst;
        if( outIx ) *outIx = i;
        return SQLITE_OK;
      }
    }
#endif
  }
  return SQLITE_ERROR;
}

/*
** Allocate space to store a compressed page.
**
** "Allocate" here simply means to determine a page and offset
** within the lower pager where the data will be stored.
*/
void ceshimAllocCmpPageSpace(
  ceshim_file *pFile,
  CeshimCmpSize cmpSz,          // Current compressed size of data for allocation
  u16 pgMapIx                   // Index of map entry to record allocation data
){
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pFile->ceshimHeader;
  CeshimCmpOfst ofst = header->currPageOfst;
  ceshim_map_entry *pMapEntry = &pFile->pPgMap[pgMapIx];
  ceshim_map_entry *pBigEndianPgMapEntry = &pFile->pBigEndianPgMap[pgMapIx];
  // Since we no longer write compressed pages to page 1, we can optimize this
  //u32 realPageSize = pFile->pageSize - (header->currPgno == 1 ? CESHIM_DB_HEADER_SIZE : 0);
  header->currPageOfst += cmpSz;
  if( header->currPageOfst > /*realPageSize*/ pFile->pageSize ){
    // current page can't hold anymore, start new page.
    ofst = 0;
    header->currPageOfst = cmpSz;
    // Make sure to not use a pgno that we allocated to a pagemap page.
    Pgno lstAllocatedPgMapPgno = pFile->mmTbl[header->mmTblCurrCnt-1].lwrPgno;
    if( header->currPgno <=  lstAllocatedPgMapPgno )
      header->currPgno = lstAllocatedPgMapPgno + 1;
    else
      header->currPgno++;
  }
  // Set data in map and in Big Endian version of map for fast save to persistent storage
  pMapEntry->lwrPgno = header->currPgno;
  pMapEntry->cmprOfst = ofst;
  pMapEntry->cmprSz = cmpSz;
  put4byte((u8 *)&pBigEndianPgMapEntry->lwrPgno, pMapEntry->lwrPgno);
  put2byte((u8 *)&pBigEndianPgMapEntry->cmprSz, pMapEntry->cmprSz);
  put2byte((u8 *)&pBigEndianPgMapEntry->cmprOfst, pMapEntry->cmprOfst);
  pFile->bPgMapDirty = 1;
}

int ceshimAddPageEntry(
  ceshim_file *pFile,
  sqlite3_int64 uppOfst,
  CeshimCmpSize cmpSz,
  CeshimCmpOfst *outCmpOfst,
  Pgno *outLwrPgno
){
  assert( (!outCmpOfst && !outLwrPgno) || (outCmpOfst && outLwrPgno) );
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pFile->ceshimHeader;

  // if no more room, start a new pagemap
  if( header->pgMapCnt == pFile->pgMapMaxCnt ){
    if( pFile->mmTblCurrIx == header->mmTblMaxCnt ){
      // We've run out of room in the master map table.
      // User will need to increase pager size.
      return CESHIM_ERROR_PAGE_SIZE_TOO_SMALL;
    }
    CeshimMMTblEntry *entry = &pFile->mmTbl[header->mmTblCurrCnt];
    entry->lwrPgno = header->currPgno+1; // use next pgno but don't incr. counter!
    header->mmTblCurrCnt++;
    header->pgMapCnt = 0;
    // reminder: can't change pInfo->mmTblCurrIx until after ceshimSwitchPageMap
    ceshimSwitchPageMap(pFile, uppOfst);
  }

  // add new page map entry
  u16 ix = header->pgMapCnt++;
  ceshim_map_entry *pPgMapEntry = &pFile->pPgMap[ix];

  // assign space to store compressed page
  ceshimAllocCmpPageSpace(pFile, cmpSz, ix);

  // for placeholder entries, set some data to zero
  if( !outLwrPgno ) pPgMapEntry->lwrPgno =  0;
  if( !outCmpOfst ) pPgMapEntry->cmprOfst = 0;

  // output params
  if( outLwrPgno ) *outLwrPgno = header->currPgno;
  if( outCmpOfst ) *outCmpOfst = pPgMapEntry->cmprOfst;

  return SQLITE_OK;
}

/*
** Add pager map entry before writing to lower pager
** to get pgno & offset for pager write operation.
**
** uppOfst - upper pager offset
** cmpSz - compressed size to save
** outLwrPgno - mapped pgno to write to
** outCmpOfst - offset to write compressed data to
**/
static int ceshimPageMapSet(
  ceshim_file *pFile,
  sqlite_int64 uppOfst,
  CeshimCmpSize cmpSz,
  Pgno *outUppPgno,
  Pgno *outLwrPgno,
  CeshimCmpOfst *outCmpOfst
){
  ceshim_info *pInfo = pFile->pInfo;
  ceshim_header *header = &pFile->ceshimHeader;
  CeshimCmpSize oldCmpSz;
  int rc = SQLITE_OK;
  u16 ix;

  assert( outUppPgno );
  assert( outLwrPgno );
  assert( outCmpOfst );

  if( (rc = ceshimPageMapGet(pFile, uppOfst, outUppPgno, outLwrPgno, outCmpOfst, &oldCmpSz, &ix))==SQLITE_OK ){
    /*
    ** We found a map entry. It's either a placeholder entry that need valid data,
    ** an outdated entry that needs updating, or a valid up-to-date entry.
    ** If the entry needs updating, we will reuse the space used to hold the previously compressed
    ** data if the compressed data now takes up less space or allocate a new space at the end of
    ** the db if it now needs more space.
    ** Any previously used and now abandoned space will need to be recovered through a vacuum process.
    */
    if( oldCmpSz==0 || cmpSz>oldCmpSz ){
      // entry found was either a placeholder or we now need more room, so allocate new space.
      ceshim_map_entry *pMapEntry = &pFile->pPgMap[ix];
      ceshimAllocCmpPageSpace(pFile, cmpSz, ix);

      *outLwrPgno = pMapEntry->lwrPgno;
      *outCmpOfst = pMapEntry->cmprOfst;
      CESHIM_PRINTF(pInfo, "Updated entry (uppOfst=%lld, lwrPgno=%lu,cmpOfst=%lu,cmpSz=%lu)\n",
        (long long)uppOfst, (unsigned long)pMapEntry->lwrPgno, (unsigned long)pMapEntry->cmprOfst, (unsigned long)pMapEntry->cmprSz);
      return SQLITE_OK;
    }else if( cmpSz<oldCmpSz ){
      // Update map entry data and keep compressed page slot. Abandoned space will need to be recovered via a vacuum operaion.
      pFile->pPgMap[ix].cmprSz = cmpSz;
      put2byte((u8 *)&pFile->pBigEndianPgMap[ix].cmprSz, cmpSz);
      pFile->bPgMapDirty = 1;
    }
    return rc;
  }else{
    sqlite3_int64 nextOfst = ((header->mmTblCurrCnt-1) * header->uppPgSz * pFile->pgMapMaxCnt) + (header->pgMapCnt * header->uppPgSz);
    while( uppOfst>nextOfst ){
      ceshimAddPageEntry(pFile, nextOfst, 0, NULL, NULL);
      CESHIM_PRINTF(pInfo, "Added intermin entry (uppOfst=%lld, lwrPgno=0,cmpOfst=0,cmpSz=0)\n", (long long)nextOfst);
      nextOfst += header->uppPgSz;
    }
    assert( uppOfst==nextOfst );
    ceshimAddPageEntry(pFile, uppOfst, cmpSz, outCmpOfst, outLwrPgno);
  }
  return SQLITE_OK;
}

/*
** Close a ceshim-file.
*/
static int ceshimClose(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  CESHIM_PRINTF(pInfo, "%s.xClose(%s)", pInfo->zVfsName, p->zFName);

  if( p->pPager ){
    if( !p->bReadOnly ){
      int nPageFile = 0;   /* Number of pages in the database file */
      sqlite3PagerPagecount(p->pPager, &nPageFile);
      assert( p->lwrPageFile==nPageFile );

      u8 buf[4];
      sqlite3Put4byte(buf, p->lwrPageFile);
      rc = ceshimWriteUncompressed(p, 1, 28, buf, 4);
      rc = ceshimSaveHeader(p);

      if( (rc = ceshimSaveMMTbl(p))==SQLITE_OK ){
        for(int i=0; i<p->nTransactions; i++){
          if( (rc = sqlite3PagerCommitPhaseOne(p->pPager, NULL, 0))==SQLITE_OK ){
            sqlite3PagerCommitPhaseTwo(p->pPager);
          }
        }
        p->nTransactions = 0;
      }
    }

    if( rc==SQLITE_OK ){
      ceshimReleasePage1(p);
      if( (rc = sqlite3PagerClose(p->pPager))==SQLITE_OK ){
        p->pPager = NULL;
        if( p->zUppJournalPath ){
          sqlite3_free(p->zUppJournalPath);
          p->zUppJournalPath = NULL;
        }
        if( p->mmTbl ){
          sqlite3_free(p->mmTbl);
          p->mmTbl = NULL;
        }
        if( p->pPgMap ){
          sqlite3_free(p->pPgMap);
          p->pPgMap = NULL;
        }
        if( p->pBigEndianPgMap ){
          sqlite3_free(p->pBigEndianPgMap);
          p->pBigEndianPgMap = NULL;
        }
        if( p->zKey ){
          sqlite3_free(p->zKey);
          p->zKey = NULL;
        }
      }
    }
  }

  if( (rc == SQLITE_OK) && ((rc = p->pReal->pMethods->xClose(p->pReal)) == SQLITE_OK) ){
    sqlite3_free((void*)p->base.pMethods);
    p->base.pMethods = NULL;
  }

  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

static void random_bytes(unsigned char *buf, int num){
  int i;
  int j = num/4;
  uint32_t *dwbuf = (uint32_t *)buf;

  srandomdev();
  for( i=0; i<j; i++ ){
    *(dwbuf+i) = (u_int32_t)random();
  }
}

/*
** Read data from a ceshim-file.
*/
static int ceshimRead(
  sqlite3_file *pFile,
  void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  u32 uppPgSz = p->ceshimHeader.uppPgSz;
  int rc;

  if( p->pPager && p->pPage1 ){
    DbPage *pPage;
    Pgno uppPgno, mappedPgno;
    CeshimCmpOfst cmprPgOfst;
    CeshimCmpSize uCmpPgSz;
    if( (rc = ceshimPageMapGet(p, iOfst, &uppPgno, &mappedPgno, &cmprPgOfst, &uCmpPgSz, NULL)) == SQLITE_OK ){
      if( rc==SQLITE_OK &&  (rc = sqlite3PagerGet(p->pPager, mappedPgno, &pPage, 0)) == SQLITE_OK ){
        CeshimMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
        CESHIM_PRINTF(pInfo, "%s.xRead(%s,pgno=%u->%u,ofst=%08lld->%u,amt=%d->%u)",
          pInfo->zVfsName, p->zFName, uppPgno, mappedPgno, iOfst, cmprPgOfst, iAmt, uCmpPgSz);
        assert( uCmpPgSz > 0 );
        int iDstAmt = uppPgSz;
        void *pUncBuf = sqlite3_malloc(iDstAmt);

        if( pUncBuf ){
          // decrypt
          void *iv =
            (char *)pMemPage->aData
            +pMemPage->dbHdrOffset
            +pMemPage->pgHdrOffset
            +cmprPgOfst;
          void *srcData = iv+pInfo->iv_sz;
          size_t tmp_csz;
          CCCryptorStatus ccStatus;

          void *pCmpBuf = sqlite3_malloc(uCmpPgSz);
          ccStatus = CCCrypt(
            kCCDecrypt,            // enc/dec
            kCCAlgorithmAES128,    // algorithm
            0,                     // options: kCCOptionPKCS7Padding, kCCOptionECBMode, 0 = no padding
            p->zKey,               // 256-bit (32-byte) key
            pInfo->key_sz,         // key length (bytes)
            iv,                    // const void *iv
            srcData,               // const void *dataIn
            uCmpPgSz-pInfo->iv_sz, // data-in length
            pCmpBuf,               // dataOut; result is written here.
            uCmpPgSz,              // The size of the dataOut buffer in bytes
            &tmp_csz               // On successful return, the number of bytes written to dataOut.
          );

          if( ccStatus==kCCSuccess ){
            pInfo->xUncompress(pInfo->pCtx, pUncBuf, &iDstAmt, pCmpBuf, (int)tmp_csz);
            assert( iDstAmt==uppPgSz );
            u16 uBufOfst = iOfst % uppPgSz;
            memcpy(zBuf, pUncBuf+uBufOfst, iAmt);
          } else rc = ccStatus;
          sqlite3_free(pUncBuf);
        }else rc = SQLITE_NOMEM;
        sqlite3PagerUnref(pPage);
      }
    }else{
      CESHIM_PRINTF(pInfo, "%s.xRead(%s,ofst=%08lld,amt=%d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
      memset(zBuf, 0, iAmt);
      rc = SQLITE_OK;
    }
  }else{
    CESHIM_PRINTF(pInfo, "%s.xRead(%s,ofst=%08lld,amt=%d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
    rc = p->pReal->pMethods->xRead(p->pReal, zBuf, iAmt, iOfst);
  }
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Write data to a ceshim-file.
*/
static int ceshimWrite(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;

  if( p->pPager ){
    DbPage *pPage;
    Pgno uppPgno, mappedPgno;
    
    if( !p->bReadOnly ){
      // compress
      int pnDest = pInfo->xCompressBound(pInfo->pCtx, iAmt);
      void* pCmpBuf = sqlite3_malloc(pnDest);
      if( pCmpBuf ){
        CeshimCmpOfst cmprPgOfst;
        pInfo->xCompress(pInfo->pCtx, pCmpBuf, &pnDest, (void *)zBuf, iAmt);
        
        // encrypt
        /* According to CCCryptor manpage: "For block ciphers, the output size will always be less than or
         equal to the input size plus the size of one block." However, there seems to be a bug as normally
         CCCrypt fails with error code kCCBufferTooSmall when the output buffer size is too small, can
         crash when size is exactly input size plus size of one block. It works with just 1 more byte.
         src: https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html */
        size_t nOutSz = pnDest+kCCBlockSizeAES128+1;
        void* pEncBuf = sqlite3_malloc((int)nOutSz);
        if( pEncBuf ){
          void *iv; // initialization vector
          CCCryptorStatus ccStatus;
          iv = pEncBuf;
          pEncBuf += pInfo->iv_sz;
          random_bytes(iv, pInfo->iv_sz);
          size_t tmp_csz;
          
          ccStatus = CCCrypt(
            kCCEncrypt,            // enc/dec
            kCCAlgorithmAES128,    // algorithm
            kCCOptionPKCS7Padding, // options: kCCOptionPKCS7Padding, kCCOptionECBMode, 0 = no padding
            p->zKey,               // 256-bit (32-byte) key
            pInfo->key_sz,         // key length (bytes)
            iv,                    // const void *iv
            pCmpBuf,               // const void *dataIn
            pnDest,                // data-in length
            pEncBuf,               // dataOut; result is written here.
            nOutSz,                // The size of the dataOut buffer in bytes
            &tmp_csz               // On successful return, the number of bytes written to dataOut.
          );
          
          if( ccStatus==kCCSuccess ){
            tmp_csz += pInfo->iv_sz;
            ceshimPageMapSet(p, iOfst, tmp_csz, &uppPgno, &mappedPgno, &cmprPgOfst);
            
            // write
            if( (rc = sqlite3PagerGet(p->pPager, mappedPgno, &pPage, 0))==SQLITE_OK ){
              CeshimMemPage *pMemPage = memPageFromDbPage(pPage, mappedPgno);
              if( (rc = ceshimPagerWrite(p, pPage))==SQLITE_OK ){
                CESHIM_PRINTF(
                  pInfo,
                  "%s.xWrite(%s, pgno=%u->%u, offset=%08lld->%06lu, amt=%06d->%06d)",
                  pInfo->zVfsName, p->zFName,
                  uppPgno, mappedPgno,
                  iOfst, (unsigned long)(pMemPage->dbHdrOffset+pMemPage->pgHdrOffset+cmprPgOfst),
                  iAmt, tmp_csz
                );
                memcpy(
                  pMemPage->aData
                  +pMemPage->dbHdrOffset
                  +pMemPage->pgHdrOffset
                  +cmprPgOfst,
                  iv,
                  tmp_csz
                );

                // Keep track of sizes of upper and lower pagers
                if( p->ceshimHeader.uppPageFile<uppPgno ) p->ceshimHeader.uppPageFile = uppPgno;
                if( p->lwrPageFile<mappedPgno ) p->lwrPageFile = mappedPgno;
              }
              sqlite3PagerUnref(pPage);
            }
          }else rc = ccStatus;
          sqlite3_free(iv);
        }else rc = SQLITE_NOMEM;
        sqlite3_free(pCmpBuf);
      }else rc = SQLITE_NOMEM;
    }else rc = SQLITE_READONLY;
  }else{
    CESHIM_PRINTF(pInfo, "%s.xWrite(%s, offset=%08lld, amt=%06d)", pInfo->zVfsName, p->zFName, iOfst, iAmt);
    rc = p->pReal->pMethods->xWrite(p->pReal, zBuf, iAmt, iOfst);
  }
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Truncate a ceshim-file.
*/
static int ceshimTruncate(sqlite3_file *pFile, sqlite_int64 size){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xTruncate(%s,%lld)", pInfo->zVfsName, p->zFName, size);
  rc = p->pReal->pMethods->xTruncate(p->pReal, size);
  CESHIM_PRINTF(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Sync a ceshim-file.
*/
static int ceshimSync(sqlite3_file *pFile, int flags){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  int i;
  char zBuf[100];
  memcpy(zBuf, "|0", 3);
  i = 0;
  if( flags & SQLITE_SYNC_FULL )        strappend(zBuf, &i, "|FULL");
  else if( flags & SQLITE_SYNC_NORMAL ) strappend(zBuf, &i, "|NORMAL");
  if( flags & SQLITE_SYNC_DATAONLY )    strappend(zBuf, &i, "|DATAONLY");
  if( flags & ~(SQLITE_SYNC_FULL|SQLITE_SYNC_DATAONLY) ){
    sqlite3_snprintf(sizeof(zBuf)-i, &zBuf[i], "|0x%x", flags);
  }
  CESHIM_PRINTF(pInfo, "%s.xSync(%s,%s)", pInfo->zVfsName, p->zFName, &zBuf[1]);
  rc = p->pReal->pMethods->xSync(p->pReal, flags);
  CESHIM_PRINTF(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Return ficticious uncompressed file size based on number of pages from source pager
** otherwise internal checks in pager.c will fail.
*/
static int ceshimFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  ceshim_header *header = &p->ceshimHeader;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xFileSize(%s)", pInfo->zVfsName, p->zFName);
  if( p->pPager ){
    *pSize = header->uppPageFile * header->uppPgSz;
    rc = SQLITE_OK;
  }else{
    rc = p->pReal->pMethods->xFileSize(p->pReal, pSize);
  }
  ceshim_print_errcode(pInfo, " -> %s,", rc);
  CESHIM_PRINTF(pInfo, " size=%lld\n", *pSize);
  return rc;
}

/*
** Return the name of a lock.
*/
static const char *lockName(int eLock){
  const char *azLockNames[] = {
     "NONE", "SHARED", "RESERVED", "PENDING", "EXCLUSIVE"
  };
  if( eLock<0 || eLock>=sizeof(azLockNames)/sizeof(azLockNames[0]) ){
    return "???";
  }else{
    return azLockNames[eLock];
  }
}

/*
** Lock a ceshim-file.
** Never lock database file for upper pager as it doesn't directly control database file anymore.
*/
static int ceshimLock(sqlite3_file *pFile, int eLock){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  CESHIM_PRINTF(pInfo, "%s.xLock(%s,%s) BYPASS", pInfo->zVfsName, p->zFName, lockName(eLock));
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Unlock a ceshim-file.
** Never unlock database file for upper pager as it doesn't directly control database file anymore.
*/
static int ceshimUnlock(sqlite3_file *pFile, int eLock){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  CESHIM_PRINTF(pInfo, "%s.xUnlock(%s,%s) BYPASS", pInfo->zVfsName, p->zFName, lockName(eLock));
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}

/*
** Check if another file-handle holds a RESERVED lock on a ceshim-file.
** Bypass checks here since upper pager doesn't directly control database file anymore.
*/
static int ceshimCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  *pResOut = 0; // not locked
  CESHIM_PRINTF(pInfo, "%s.xCheckReservedLock(%s,%d) BYPASS", pInfo->zVfsName, p->zFName);
  ceshim_print_errcode(pInfo, " -> %s", rc);
  CESHIM_PRINTF(pInfo, ", out=%d\n", *pResOut);
  CESHIM_PRINTF(pInfo, "\n");
  return rc;
}

static int ceshimPragma(sqlite3_file *pFile, const char *op, const char *arg){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc = SQLITE_OK;
  if( strcmp(op, "page_size")==0 ){
    p->ceshimHeader.uppPgSz = (u32)sqlite3Atoi(arg);
  }
  return rc;
}

/*
** File control method. For custom operations on a ceshim-file.
*/
static int ceshimFileControl(sqlite3_file *pFile, int op, void *pArg){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  char zBuf[100];
  char *zOp;
  switch( op ){
    case SQLITE_FCNTL_LOCKSTATE:    zOp = "LOCKSTATE";          break;
    case SQLITE_GET_LOCKPROXYFILE:  zOp = "GET_LOCKPROXYFILE";  break;
    case SQLITE_SET_LOCKPROXYFILE:  zOp = "SET_LOCKPROXYFILE";  break;
    case SQLITE_LAST_ERRNO:         zOp = "LAST_ERRNO";         break;
    case SQLITE_FCNTL_SIZE_HINT: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "SIZE_HINT,%lld",
                       *(sqlite3_int64*)pArg);
      zOp = zBuf;
      break;
    }
    case SQLITE_FCNTL_CHUNK_SIZE: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "CHUNK_SIZE,%d", *(int*)pArg);
      zOp = zBuf;
      break;
    }
    case SQLITE_FCNTL_FILE_POINTER: zOp = "FILE_POINTER";       break;
    case SQLITE_FCNTL_SYNC_OMITTED: zOp = "SYNC_OMITTED";       break;
    case SQLITE_FCNTL_WIN32_AV_RETRY: zOp = "WIN32_AV_RETRY";   break;
    case SQLITE_FCNTL_PERSIST_WAL:  zOp = "PERSIST_WAL";        break;
    case SQLITE_FCNTL_OVERWRITE:    zOp = "OVERWRITE";          break;
    case SQLITE_FCNTL_VFSNAME:      zOp = "VFSNAME";            break;
    case SQLITE_FCNTL_TEMPFILENAME: zOp = "TEMPFILENAME";       break;
    case SQLITE_FCNTL_DB_UNCHANGED: zOp = "DB_UNCHANGED";       break;
    case SQLITE_FCNTL_PRAGMA: {
      const char *const* a = (const char*const*)pArg;
      sqlite3_snprintf(sizeof(zBuf), zBuf, "PRAGMA,[%s,%s]",a[1],a[2]);
      zOp = zBuf;
      ceshimPragma(pFile, a[1], a[2]);
      break;
    }
    case SQLITE_FCNTL_MMAP_SIZE: {
      sqlite3_snprintf(sizeof(zBuf), zBuf, "SQLITE_FCNTL_MMAP_SIZE,%d", *(int*)pArg);
      zOp = zBuf;
      break;
    }
    default: {
      sqlite3_snprintf(sizeof zBuf, zBuf, "%d", op);
      zOp = zBuf;
      break;
    }
  }
  CESHIM_PRINTF(pInfo, "%s.xFileControl(%s,%s)", pInfo->zVfsName, p->zFName, zOp);
  rc = p->pReal->pMethods->xFileControl(p->pReal, op, pArg);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  if( op==SQLITE_FCNTL_VFSNAME && rc==SQLITE_OK ){
    *(char**)pArg = sqlite3_mprintf("ceshim.%s/%z",
                                    pInfo->zVfsName, *(char**)pArg);
  }
  if( (op==SQLITE_FCNTL_PRAGMA || op==SQLITE_FCNTL_TEMPFILENAME)
   && rc==SQLITE_OK && *(char**)pArg ){
    CESHIM_PRINTF(pInfo, "%s.xFileControl(%s,%s) returns %s", pInfo->zVfsName, p->zFName, zOp, *(char**)pArg);
  }
  return rc;
}

/*
** Return the sector-size in bytes for a ceshim-file.
*/
static int ceshimSectorSize(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xSectorSize(%s)", pInfo->zVfsName, p->zFName);
  rc = p->pReal->pMethods->xSectorSize(p->pReal);
  CESHIM_PRINTF(pInfo, " -> %d\n", rc);
  return rc;
}

/*
** Return the device characteristic flags supported by a ceshim-file.
*/
static int ceshimDeviceCharacteristics(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xDeviceCharacteristics(%s)", pInfo->zVfsName, p->zFName);
  rc = p->pReal->pMethods->xDeviceCharacteristics(p->pReal);
  CESHIM_PRINTF(pInfo, " -> 0x%08x\n", rc);
  return rc;
}

/*
** Shared-memory operations.
*/
static int ceshimShmLock(sqlite3_file *pFile, int ofst, int n, int flags){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  char zLck[100];
  int i = 0;
  memcpy(zLck, "|0", 3);
  if( flags & SQLITE_SHM_UNLOCK )    strappend(zLck, &i, "|UNLOCK");
  if( flags & SQLITE_SHM_LOCK )      strappend(zLck, &i, "|LOCK");
  if( flags & SQLITE_SHM_SHARED )    strappend(zLck, &i, "|SHARED");
  if( flags & SQLITE_SHM_EXCLUSIVE ) strappend(zLck, &i, "|EXCLUSIVE");
  if( flags & ~(0xf) ){
     sqlite3_snprintf(sizeof(zLck)-i, &zLck[i], "|0x%x", flags);
  }
  CESHIM_PRINTF(pInfo, "%s.xShmLock(%s,ofst=%d,n=%d,%s)", pInfo->zVfsName, p->zFName, ofst, n, &zLck[1]);
  rc = p->pReal->pMethods->xShmLock(p->pReal, ofst, n, flags);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}
static int ceshimShmMap(
  sqlite3_file *pFile,
  int iRegion,
  int szRegion,
  int isWrite,
  void volatile **pp
){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xShmMap(%s,iRegion=%d,szRegion=%d,isWrite=%d,*)", pInfo->zVfsName, p->zFName, iRegion, szRegion, isWrite);
  rc = p->pReal->pMethods->xShmMap(p->pReal, iRegion, szRegion, isWrite, pp);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}
static void ceshimShmBarrier(sqlite3_file *pFile){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  CESHIM_PRINTF(pInfo, "%s.xShmBarrier(%s)\n", pInfo->zVfsName, p->zFName);
  p->pReal->pMethods->xShmBarrier(p->pReal);
}
static int ceshimShmUnmap(sqlite3_file *pFile, int delFlag){
  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = p->pInfo;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xShmUnmap(%s,delFlag=%d)", pInfo->zVfsName, p->zFName, delFlag);
  rc = p->pReal->pMethods->xShmUnmap(p->pReal, delFlag);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  return rc;
}


static void ceshimPageReinit(DbPage *pData){

}

static int ceshimSetKey(char **pKey, const char *pExpr){
  int i, n;
  int rc = SQLITE_OK;
  const char *z;

  if( (pExpr[0]=='x' || pExpr[0]=='X') && pExpr[1]=='\'' ){
    z = &pExpr[2];
    if( *pKey ){
      sqlite3_free(pKey);
      *pKey = NULL;
    }
    n = sqlite3Strlen30(z) - 1;
    if( z[n]=='\'' ){
      *pKey = (char *)sqlite3_malloc(n/2 + 1);
      n--;
      if( *pKey ){
        for(i=0; i<n; i+=2){
          (*pKey)[i/2] = (sqlite3HexToInt(z[i])<<4) | sqlite3HexToInt(z[i+1]);
        }
        (*pKey)[i/2] = 0;
      }else rc = SQLITE_NOMEM;
    }else rc = CESHIM_ERROR_MALFORMED_KEY;
  }else rc = CESHIM_ERROR_MALFORMED_KEY;
  return rc;
}

int ceshim_set_vfs_key(const char *zName, const char *pExpr){
  if( zName && pExpr ){
    sqlite3_vfs *pVfs = sqlite3_vfs_find(zName);
    if( pVfs==0 ) return SQLITE_NOTFOUND;
    ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
    if( pInfo ) return ceshimSetKey(&pInfo->zKey, pExpr);
  }
  return SQLITE_ERROR;
}

/*
** Open a ceshim file handle.
*/
static int ceshimOpen(
    sqlite3_vfs *pVfs,
    const char *_zName,
    sqlite3_file *pFile,
    int flags,
    int *pOutFlags
){
  u8 nReserve;
  int rc;

  ceshim_file *p = (ceshim_file *)pFile;
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  u32 nParamBlockSz = 0;

  // Zero-initialize
  int offset = sizeof(p->base)+sizeof(*(p->pReal));
  int size = sizeof(*p)-offset;
  memset((void*)p + offset, 0, size);
  
  // Initialize
  p->pInfo = pInfo;
  const char *zName = ceshimMapPath(p, _zName, NULL);
  p->zFName = zName ? fileTail(zName) : "<temp>";
  p->pReal = (sqlite3_file *)&p[1];
  p->ceshimHeader.schema = CESHIM_FILE_SCHEMA_NO;
  p->ceshimHeader.currPgno = CESHIM_FIRST_MAPPED_PAGE;
  p->ceshimHeader.uppPgSz = SQLITE_DEFAULT_PAGE_SIZE;
  
  // We need this for import
  pInfo->pFile = p;

  // Set readonly flag
  if( pInfo->cerod_activated && strcmp(pInfo->zVfsName, "ceshim-cerod")==0 ){
    p->bReadOnly = 1;
  }else if( flags & SQLITE_OPEN_READONLY ){
    p->bReadOnly = 1;
  }

  // Process URI parameters
  if( flags & SQLITE_OPEN_URI ){
    // block_size
    const char *zParamBlockSize = sqlite3_uri_parameter(_zName, "block_size");
    if( zParamBlockSize ) nParamBlockSz = (u32)sqlite3Atoi(zParamBlockSize);
    // key
    const char *zParamKey = sqlite3_uri_parameter(_zName, "key");
    if( zParamKey ) rc = ceshimSetKey(&p->zKey, zParamKey);
  }

  if( pInfo->zKey && !p->zKey ){
    p->zKey = (char *)sqlite3_malloc(pInfo->key_sz);
    memcpy(p->zKey, pInfo->zKey, pInfo->key_sz);
  }

  // open file
  rc = pRoot->xOpen(pRoot, zName, p->pReal, flags, pOutFlags);
  CESHIM_PRINTF(pInfo, "%s.xOpen(%s,flags=0x%x)",pInfo->zVfsName, p->zFName, flags);

  if( rc==SQLITE_OK ){
    // hook up I/O methods
    if( p->pReal->pMethods ){
      sqlite3_io_methods *pNew = sqlite3_malloc( sizeof(*pNew) );
      const sqlite3_io_methods *pSub = p->pReal->pMethods;
      memset(pNew, 0, sizeof(*pNew));
      pNew->iVersion = pSub->iVersion;
      pNew->xClose = ceshimClose;
      pNew->xRead = ceshimRead;
      pNew->xWrite = ceshimWrite;
      pNew->xTruncate = ceshimTruncate;
      pNew->xSync = ceshimSync;
      pNew->xFileSize = ceshimFileSize;
      pNew->xLock = ceshimLock;
      pNew->xUnlock = ceshimUnlock;
      pNew->xCheckReservedLock = ceshimCheckReservedLock;
      pNew->xFileControl = ceshimFileControl;
      pNew->xSectorSize = ceshimSectorSize;
      pNew->xDeviceCharacteristics = ceshimDeviceCharacteristics;
      if( pNew->iVersion>=2 ){
        pNew->xShmMap = pSub->xShmMap ? ceshimShmMap : 0;
        pNew->xShmLock = pSub->xShmLock ? ceshimShmLock : 0;
        pNew->xShmBarrier = pSub->xShmBarrier ? ceshimShmBarrier : 0;
        pNew->xShmUnmap = pSub->xShmUnmap ? ceshimShmUnmap : 0;
      }
      pFile->pMethods = pNew;
    }

    // create pager to handle I/O to compressed/encrypted underlying db
    if( flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TRANSIENT_DB) ){
      if( (rc = sqlite3PagerOpen(pInfo->pRootVfs, &p->pPager, zName, EXTRA_SIZE, 0, flags, ceshimPageReinit))==SQLITE_OK){
        if( rc==SQLITE_OK ){
          sqlite3PagerSetJournalMode(p->pPager, PAGER_JOURNALMODE_DELETE);
//          sqlite3PagerJournalSizeLimit(p->pPager, -1);
//          rc = sqlite3PagerLockingMode(p->pPager, PAGER_LOCKINGMODE_NORMAL);
//          sqlite3PagerSetMmapLimit(pBt->pPager, db->szMmap); /* advisory, except if 0 */
          if( (rc = sqlite3PagerReadFileheader(p->pPager,sizeof(p->zDbHeader),p->zDbHeader)) == SQLITE_OK ){
            p->pageSize = (p->zDbHeader[16]<<8) | (p->zDbHeader[17]<<16);
            if( p->pageSize<512 || p->pageSize>SQLITE_MAX_PAGE_SIZE
               || ((p->pageSize-1)&p->pageSize)!=0 ){
              p->pageSize = nParamBlockSz; // if 0, sqlite3PagerSetPagesize will set page size
              nReserve = 0;
            }else{
              nReserve = p->zDbHeader[20];
              p->lwrPageFile = sqlite3Get4byte(p->zDbHeader+28);
            }
            sqlite3PagerSetMmapLimit(p->pPager, 0);
            if( (rc = sqlite3PagerSetPagesize(p->pPager, &p->pageSize, nReserve)) == SQLITE_OK ){
              p->usableSize = p->pageSize - nReserve;
              sqlite3PagerSetCachesize(p->pPager, SQLITE_DEFAULT_CACHE_SIZE);
              rc = ceshimPagerLock(p);
            }
          }
        }else{
          ceshimClose(pFile);
        }
      }
    }
  }

  ceshim_print_errcode(pInfo, " -> %s", rc);
  if( pOutFlags ){
    CESHIM_PRINTF(pInfo, ", outFlags=0x%x\n", *pOutFlags);
  }else{
    CESHIM_PRINTF(pInfo, "\n");
  }
  return rc;
}

/*
** Delete the file located at zPath. If the dirSync argument is true,
** ensure the file-system modifications are synced to disk before
** returning.
*/
static int ceshimDelete(sqlite3_vfs *pVfs, const char *_zPath, int dirSync){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  bool bMustRelease;
  
  char *zPath = ceshimMapPath(NULL, _zPath, &bMustRelease);
  CESHIM_PRINTF(pInfo, "%s.xDelete(\"%s\",%d)", pInfo->zVfsName, zPath, dirSync);
  rc = pRoot->xDelete(pRoot, zPath, dirSync);
  ceshim_print_errcode(pInfo, " -> %s\n", rc);
  if (bMustRelease)sqlite3_free(zPath);
  return rc;
}

/*
** Test for access permissions.
** Return true via *pResOut if the requested permission
** is available, or false otherwise.
*/
static int ceshimAccess(
  sqlite3_vfs *pVfs,
  const char *_zPath,
  int flags,
  int *pResOut
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  bool bMustRelease;
  const char *zPath = ceshimMapPath(NULL, _zPath, &bMustRelease);
  int rc = SQLITE_OK;
  
  CESHIM_PRINTF(pInfo, "%s.xAccess(\"%s\",%d)", pInfo->zVfsName, zPath, flags);
  rc = pRoot->xAccess(pRoot, zPath, flags, pResOut);
  ceshim_print_errcode(pInfo, " -> %s", rc);
  CESHIM_PRINTF(pInfo, ", out=%d\n", *pResOut);
  if (bMustRelease) sqlite3_free(zPath);
  return rc;
}

/*
** Populate buffer zOut with the full canonical pathname corresponding
** to the pathname in zPath. zOut is guaranteed to point to a buffer
** of at least (DEVSYM_MAX_PATHNAME+1) bytes.
*/
static int ceshimFullPathname(
  sqlite3_vfs *pVfs,
  const char *zPath,
  int nOut,
  char *zOut
){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  int rc;
  CESHIM_PRINTF(pInfo, "%s.xFullPathname(\"%s\")", pInfo->zVfsName, zPath);
  rc = pRoot->xFullPathname(pRoot, zPath, nOut, zOut);
  ceshim_print_errcode(pInfo, " -> %s", rc);
  CESHIM_PRINTF(pInfo, ", out=\"%.*s\"\n", nOut, zOut);
  return rc;
}

/*
** Open the dynamic library located at zPath and return a handle.
*/
static void *ceshimDlOpen(sqlite3_vfs *pVfs, const char *zPath){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CESHIM_PRINTF(pInfo, "%s.xDlOpen(\"%s\")\n", pInfo->zVfsName, zPath);
  return pRoot->xDlOpen(pRoot, zPath);
}

/*
** Populate the buffer zErrMsg (size nByte bytes) with a human readable
** utf-8 string describing the most recent error encountered associated
** with dynamic libraries.
*/
static void ceshimDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CESHIM_PRINTF(pInfo, "%s.xDlError(%d)", pInfo->zVfsName, nByte);
  pRoot->xDlError(pRoot, nByte, zErrMsg);
  CESHIM_PRINTF(pInfo, " -> \"%s\"", zErrMsg);
}

/*
** Return a pointer to the symbol zSymbol in the dynamic library pHandle.
*/
static void (*ceshimDlSym(sqlite3_vfs *pVfs,void *p,const char *zSym))(void){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CESHIM_PRINTF(pInfo, "%s.xDlSym(\"%s\")\n", pInfo->zVfsName, zSym);
  return pRoot->xDlSym(pRoot, p, zSym);
}

/*
** Close the dynamic library handle pHandle.
*/
static void ceshimDlClose(sqlite3_vfs *pVfs, void *pHandle){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CESHIM_PRINTF(pInfo, "%s.xDlOpen()\n", pInfo->zVfsName);
  pRoot->xDlClose(pRoot, pHandle);
}

/*
** Populate the buffer pointed to by zBufOut with nByte bytes of
** random data.
*/
static int ceshimRandomness(sqlite3_vfs *pVfs, int nByte, char *zBufOut){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  CESHIM_PRINTF(pInfo, "%s.xRandomness(%d)\n", pInfo->zVfsName, nByte);
  return pRoot->xRandomness(pRoot, nByte, zBufOut);
}

/*
** Sleep for nMicro microseconds. Return the number of microseconds
** actually slept.
*/
static int ceshimSleep(sqlite3_vfs *pVfs, int nMicro){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xSleep(pRoot, nMicro);
}

/*
** Return the current time as a Julian Day number in *pTimeOut.
*/
static int ceshimCurrentTime(sqlite3_vfs *pVfs, double *pTimeOut){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xCurrentTime(pRoot, pTimeOut);
}
static int ceshimCurrentTimeInt64(sqlite3_vfs *pVfs, sqlite3_int64 *pTimeOut){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xCurrentTimeInt64(pRoot, pTimeOut);
}

/*
** Return the emost recent error code and message
*/
static int ceshimGetLastError(sqlite3_vfs *pVfs, int iErr, char *zErr){
  ceshim_info *pInfo = (ceshim_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  return pRoot->xGetLastError(pRoot, iErr, zErr);
}

/*
** Clients invoke ceshim_register to construct a new ceshim.
**
** Return SQLITE_OK on success.
**
** SQLITE_NOMEM is returned in the case of a memory allocation error.
** SQLITE_NOTFOUND is returned if zOldVfsName does not exist.
*/
int _ceshim_register(
  const char *zName,
  const char *zParent,
  void *pCtx,
  int (*xCompressBound)(void *, int nSrc),
  int (*xCompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xUncompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int makeDflt,                     // Made default VPS to use when not specified
  int cerodActivated                // CEROD is only read-only
){
  sqlite3_vfs *pNew;
  sqlite3_vfs *pRoot;
  ceshim_info *pInfo;
  int nName;
  int nByte;

  // Allow parameters to be passed with database filename in URI form.
  sqlite3_config(SQLITE_CONFIG_URI, 1);
  
  pRoot = sqlite3_vfs_find(zParent);
  if( pRoot==0 ) return SQLITE_NOTFOUND;
  nName = (int)strlen(zName);

  // Allocate memory for a new sqlite3_vfs, ceshim_info and the name of the new VFS.
  nByte = sizeof(*pNew) + sizeof(*pInfo) + nName + 1;
  pNew = sqlite3_malloc( nByte );
  if( pNew==0 ) return SQLITE_NOMEM;
  memset(pNew, 0, nByte);

  // Hook up the rest of the allocated memory
  pInfo = (ceshim_info*)&pNew[1];
  pNew->zName = (char*)&pInfo[1];

  // Intialize data
  memcpy((char*)&pInfo[1], zName, nName+1);
  pNew->iVersion = pRoot->iVersion;
  pNew->szOsFile = pRoot->szOsFile + sizeof(ceshim_file);
  pNew->mxPathname = pRoot->mxPathname;
  pNew->pAppData = pInfo;
  pNew->xOpen = ceshimOpen;
  pNew->xDelete = ceshimDelete;
  pNew->xAccess = ceshimAccess;
  pNew->xFullPathname = ceshimFullPathname;
  pNew->xDlOpen = pRoot->xDlOpen==0 ? 0 : ceshimDlOpen;
  pNew->xDlError = pRoot->xDlError==0 ? 0 : ceshimDlError;
  pNew->xDlSym = pRoot->xDlSym==0 ? 0 : ceshimDlSym;
  pNew->xDlClose = pRoot->xDlClose==0 ? 0 : ceshimDlClose;
  pNew->xRandomness = ceshimRandomness;
  pNew->xSleep = ceshimSleep;
  pNew->xCurrentTime = ceshimCurrentTime;
  pNew->xGetLastError = pRoot->xGetLastError==0 ? 0 : ceshimGetLastError;
  if( pNew->iVersion>=2 ){
    pNew->xCurrentTimeInt64 = pRoot->xCurrentTimeInt64==0 ? 0 : ceshimCurrentTimeInt64;
    if( pNew->iVersion>=3 ){
      pNew->xSetSystemCall = 0;
      pNew->xGetSystemCall = 0;
      pNew->xNextSystemCall = 0;
    }
  }
  pInfo->cerod_activated = cerodActivated;
  pInfo->pRootVfs = pRoot;
  pInfo->zVfsName = pNew->zName;
  pInfo->pCeshimVfs = pNew;
  pInfo->pCtx = pCtx;
  pInfo->xCompressBound = xCompressBound;
  pInfo->xCompress = xCompress;
  pInfo->xUncompress = xUncompress;
  pInfo->key_sz = kCCKeySizeAES256;  // 32 bytes
  pInfo->iv_sz = kCCBlockSizeAES128; // 16 bytes

  CESHIM_PRINTF(pInfo, "%s.enabled_for(\"%s\")\n", pInfo->zVfsName, pRoot->zName);
  return sqlite3_vfs_register(pNew, makeDflt);
}

int ceshim_register(
  const char *zName,                // Name of the newly constructed VFS
  const char *zParent,              // Name of the underlying VFS
  void *pCtx,                       // Used to pass contextual data to compression routines
  int (*xCompressBound)(void *, int nSrc),
  int (*xCompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc),
  int (*xUncompress)(void *, char *aDest, int *pnDest, char *aSrc, int nSrc)
){
  return _ceshim_register(zName, zParent, pCtx, xCompressBound, xCompress, xUncompress, 0 ,0);
}

int ceshim_unregister(const char *zName){
  sqlite3_vfs *pVfs = sqlite3_vfs_find(zName);
  if( pVfs ){
    //ceshim_info *pInfo = (ceshim_info *)pVfs->pAppData;
    sqlite3_free(pVfs);
    return SQLITE_OK;
  }
  return SQLITE_NOTFOUND;
}

int ceshimDefaultCompressBound(void *pCtx, int nByte){
  return (int)compressBound(nByte);
}

int ceshimDefaultCompress(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc){
  uLongf n = *pnDest;             /* In/out buffer size for compress() */
  int rc;                         /* compress() return code */

  rc = compress((Bytef*)aDest, &n, (Bytef*)aSrc, nSrc);
  *pnDest = (int)n;
  return (rc==Z_OK ? SQLITE_OK : SQLITE_ERROR);
}

int ceshimDefaultUncompress(void *pCtx, char *aDest, int *pnDest, char *aSrc, int nSrc){
  uLongf n = *pnDest;             /* In/out buffer size for uncompress() */
  int rc;                         /* uncompress() return code */

  rc = uncompress((Bytef*)aDest, &n, (Bytef*)aSrc, nSrc);
  *pnDest = (int)n;
  return (rc==Z_OK ? SQLITE_OK : SQLITE_ERROR);
}

SQLITE_API void SQLITE_STDCALL sqlite3_activate_cerod(
  const char *zPassPhrase        /* Activation phrase */
){
  // Activate this VPS using the builtin "PRAGMA activate_extensions('cerod-');"
  _ceshim_register("ceshim-cerod", NULL, NULL, ceshimDefaultCompressBound, ceshimDefaultCompress, ceshimDefaultUncompress, 1 /* use as default VPS */, 1 /* ensure readonly */);
}

int ceshimBuild(const char *srcDbPath, const char *destUri){
  int rc = SQLITE_ERROR;
  unsigned char zDbHeader[100];
  
  // _ceshim_register must be done early enough to avoid SQLITE_MISUSE error
  if( (rc = _ceshim_register("ceshim-build", NULL, NULL, ceshimDefaultCompressBound, ceshimDefaultCompress, ceshimDefaultUncompress, 0, 0))==SQLITE_OK ){
    sqlite3_vfs *pVfs = sqlite3_vfs_find(NULL);
    if( pVfs ){
      Pager *pPager;
      int vfsFlags = SQLITE_OPEN_READONLY | SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_URI;
      if( (rc = sqlite3PagerOpen(pVfs, &pPager, srcDbPath, EXTRA_SIZE, 0, vfsFlags, ceshimPageReinit))==SQLITE_OK ){
        sqlite3PagerSetJournalMode(pPager, PAGER_JOURNALMODE_OFF);
        if( (rc = sqlite3PagerReadFileheader(pPager,sizeof(zDbHeader),zDbHeader)) == SQLITE_OK ){
          u32 pageSize = (zDbHeader[16]<<8) | (zDbHeader[17]<<16);
          if( pageSize>=512 && pageSize<=SQLITE_MAX_PAGE_SIZE  // validate range
            && ((pageSize-1)&pageSize)==0 ){                   // validate page size is a power of 2
            u8 nReserve = zDbHeader[20];
            if( (rc = sqlite3PagerSetPagesize(pPager, &pageSize, nReserve)) == SQLITE_OK ){
              u32 fileChangeCounter = sqlite3Get4byte(zDbHeader+24);
              u32 pageCount = sqlite3Get4byte(zDbHeader+28);
              u32 schemaFormat = sqlite3Get4byte(zDbHeader+44);
              u32 versionValidForNumber = sqlite3Get4byte(zDbHeader+92);
              
              // If we didn't get page count, figure it out from the file size
              if( !(pageCount>0 && fileChangeCounter==versionValidForNumber) ){
                struct stat st;
                if( stat(srcDbPath, &st)==0 ){
                  off_t size = st.st_size;
                  pageCount = st.st_size/pageSize;
                }
              }
              
              // lock pager, prepare to read
              if( rc==SQLITE_OK && (rc = sqlite3PagerSharedLock(pPager))==SQLITE_OK ){
                // get destination ready to receive data
                sqlite3 *pDb;
                if( (rc = sqlite3_open_v2(destUri, &pDb, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, "ceshim-build"))==SQLITE_OK ){
                  sqlite3_vfs *pVfs = sqlite3_vfs_find("ceshim-build");
                  ceshim_info *pInfo = (ceshim_info *)pVfs->pAppData;
                  // import all pages
                  for(Pgno i=0; i<pageCount; i++){
                    // read source page
                    DbPage *pPage;
                    rc = sqlite3PagerGet(pPager, i+1, &pPage, 0);
                    if( rc==SQLITE_OK ){
                      // write destination page
                      void *pData = sqlite3PagerGetData(pPage);
                      rc = ceshimWrite((sqlite3_file *)pInfo->pFile, pData, pageSize, pageSize*i);
                      if (i>1) sqlite3PagerUnref(pPage);
                      if( rc != SQLITE_OK ) break;
                    }else{
                      break;
                    }
                  }
                  rc = sqlite3_close(pDb);
                }
              }
            }
          }
        }else{
          rc = SQLITE_CORRUPT;
        }
      }
    }
  }
  return rc;
}
