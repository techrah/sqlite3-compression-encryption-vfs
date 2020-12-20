# CEVFS: Compression & Encryption VFS for SQLite 3
CEVFS is a SQLite 3 Virtual File System for compressing and encrypting data at the pager level. Once set up, you use SQLite as you normally would and the compression and encryption is transparently handled during database read/write operations via the SQLite pager.

## Introduction
CEVFS is an open source SQLite extension that combines some of the functionality of [CEROD](http://www.sqlite.org/cerod/doc/trunk/www/index.wiki) and [ZIPVFS](http://www.sqlite.org/zipvfs/doc/trunk/www/index.wiki) into one package. Even though no testing has been done yet beyond macOS and iOS, the goal is to make it as portable as SQLite itself -- with the help of the community.

CEVFS gives you convenient hooks into SQLite that allow you to easily implement your own compression and encryption functions. As different operating systems come preloaded with different compression and encryption libraries, no default compression or encryption functions are supplied with CEVFS. The **cevfs_example** project uses Zlib and CCCryptor (3cc), both of which are included in macOS and iOS.

## How It Works
CEVFS is a [SQLite Virtual File System](http://www.sqlite.org/vfs.html) which uses its own pager and is inserted between the pager used by the b-tree (herein referred to as the upper pager) and the OS interface. This allows it to intercept the read/write operations to the database and seamlessly compress/decompress and encrypt/decrypt the data. See "[How ZIPVFS Works](http://www.sqlite.org/zipvfs/doc/trunk/www/howitworks.wiki)" for more details. Unlike ZIPVFS, the page size of the pager used by CEVFS (herein referred to as the lower pager) is determined when the CEVFS database is created and is a persistent property of the database. WAL mode is not yet supported.

## How To Build

#### Get the SQLite Source Code
1. Go to the [Downloads page](http://www.sqlite.org/download.html).
1. Select one of the geographically located sites ([Dallas TX](http://www.sqlite.org/cgi/src), [Newark NJ](http://www2.sqlite.org/cgi/src), [Fremont CA](http://www3.sqlite.org/cgi/src)) from the Source Code Repositories section at the bottom of the page.
1. Select the **Tags** tab at the top of the page.
1. Select the SQLite version you're interested in.
1. Select the Fossil SHA1 (10-char hex string) commit link.
1. Finally, download the tarball or ZIP archive.

_For easy reference, it will be assumed that the SQLite source code is in the `sqlite/` directory._

#### Create the Amalgamation file.
1. Decompress the archive and `cd` to the root of the unarchived directory.
1. `./configure`
1. `make sqlite3.c`

#### Build a Static Library
1. Create a temporary `build` directory and `cd` to it.
1. Copy `sqlite3.c`, `cevfs.c` and `cevfs.h` to the `build` directory.
1. Combine the files: `cat sqlite3.c cevfs.c > cevfs-all.c`
1. Compile: `clang -c cevfs-all.c -o sqlite3.o -Os`
1. Create static lib: `libtool -static sqlite3.o -o sqlite3.a`

### Creating a Command-Line Build Tool
If you are using macOS, you can use the `cevfs_build` example which implements compression using Zlib and encryption using 3cc. Otherwise, modify the _xFunctions_ first to accommodate your operating system.

Copy the following files to your temporary build directory:
- sqlite/sqlite3.c
- cevfs/cevfs.c
- cevfs\_build/cevfs\_build.c
- cevfs_build/xMethods.c

Build:
```
build> $ cat sqlite3.c cevfs.c > cevfs-all.c
build> $ clang cevfs-all.c cevfs_build.c -O2 -o cevfs_build -lz
```

Then to create a CEVFS database:
```
./cevfs_build UNCOMPRESSED COMPRESSED VFS_NAME KEY
```

parameters:
- **UNCOMPRESSED**: path to uncompressed database
- **COMPRESSED**: path to new compressed database
- **VFS_NAME**: name to embed in header (10 chars. max.)
- **KEY**: encryption key

E.g.:

```
./cevfs_build myDatabase.db myNewDatabase.db default "x'2F3A995FCE317EA22F3A995FCE317EA22F3A995FCE317EA22F3A995FCE317EA2'"
```

(hex key is 32 pairs of 2-digit hex values)

You can also try different block sizes and compare the sizes of the new databases to see which one uses less space. To specify the block size, specify the destination path using a URI and append `?block_size=<block size>`:

```
./cevfs_build myDatabase.db "file:///absolute/path/to/myNewDatabase.db?block_size=4096" default "x'2F3A995FCE317EA2...'"
```

### Creating a Custom Version of SQLite
It is helpful to have a custom command-line version of `sqlite3` on your development workstation for opening/testing your newly created databases.

Copy the following files to your temporary `build` directory.
- sqlite3.c (from SQLite source)
- shell.c (from SQLite source)
- cevfs/cevfs.c
- cevfs_build/cevfs_mod.c
- cevfs_build/xMethods.c

Again, modify your _xFunctions_ to accommodate your operating system. You may also need to install the Readline lib.

Build:
```
build> $ cat sqlite3.c cevfs.c cevfs_mod.c > cevfs-all.c
build> $ clang cevfs-all.c shell.c -DSQLITE_ENABLE_CEROD=1 -DHAVE_READLINE=1 -O2 -o sqlite3 -lz -lreadline
```

_If you get errors related to implicit declaration of functions under C99, you can add `-Wno-implicit-function-declaration` to disable them._

Then, to open a CEVFS database:

```
$ ./sqlite3
sqlite> PRAGMA activate_extensions("cerod-x'<your hex key goes here>'");
sqlite> .open path/to/your/cevfs/db
```

By specifying `SQLITE_ENABLE_CEROD` we can make use of an API hook that's built into SQLite for the CEROD extension that will allow you to conveniently activate CEVFS. It has the following signature:

```
SQLITE_API void SQLITE_STDCALL sqlite3_activate_cerod(const char *zPassPhrase);
```

If you are using CEVFS, chances are that you are _not_ currently making use of this API hook. You can use the `const char *` param to pass something other than the intended activation key, such as the encryption key. This `sqlite3_activate_cerod` function has been implemented in `cevfs_build/cevfs_mod.c` as an example. Alternatively, you can roll out your own [Run-Time Loadable Extension](http://www.sqlite.org/loadext.html) for use with a standard SQLite 3 build.

## Limitations

- WAL mode is not (yet) supported.
- Free nodes are not managed which could result in wasted space. Not an issue if the database you create with `cevfs_build()` is intended to be used as a read-only database.
- VACUUM not yet implemented to recover lost space.

## SQLite3 Compatible Versions

|Version|Combatibility|
|-|-|
|3.10.2|Most development was originally with this version.|
|3.11.x|Testing OK. No changes were required.|
|3.12.0 - 3.15.2|Default pager page size changed. CEVFS updated for these versions.|
|3.16.0 - 3.34.0|`sqlite3PagerClose` API signature changed: CEVFS updated for these versions.|

## Contributing to the project
If you would like to contribute back to the project, please fork the repo and submit pull requests. For more information, please read this [wiki page](https://github.com/ryanhomer/sqlite3-compression-encryption-vfs/wiki/Developing-in-Xcode)

Here are some things that need to be implemented:
- Proper mutex & multi-threading support
- TCL unit tests
- WAL support
- Full text indexing support
- Keep track of free space lost when data is moved to a new page and reuse free space during subsequent write operations
- Implement database compacting (using 'vacuum' keyword if possible)
