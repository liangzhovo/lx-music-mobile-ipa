#import "FileSystemModule.h"
#import <React/RCTLog.h>
#import <React/RCTUtils.h>
#import <CommonCrypto/CommonDigest.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import <zlib.h>

@implementation FileSystemModule

RCT_EXPORT_MODULE()

// ---------- 目录常量（对应 JS Dirs） ----------
- (NSDictionary *)constantsToExport {
  NSArray<NSString *> *cachePaths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
  NSArray<NSString *> *docPaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
  return @{
    @"CacheDir": [cachePaths firstObject] ?: NSTemporaryDirectory(),
    @"DocumentDir": [docPaths firstObject] ?: NSHomeDirectory(),
    @"MainBundleDir": [[NSBundle mainBundle] bundlePath],
    // Android only 概念，iOS 给空字符串避免 undefined 崩溃
    @"SDCardDir": @"",
  };
}

+ (BOOL)requiresMainQueueSetup {
  return NO;
}

// ---------- 工具 ----------
static NSString *PathDir(NSString *path) {
  return [path stringByDeletingLastPathComponent];
}

static NSDictionary *FileTypeDict(NSString *path, NSFileManager *fm) {
  NSError *err = nil;
  NSDictionary *attrs = [fm attributesOfItemAtPath:path error:&err];
  BOOL isDir = NO;
  [fm fileExistsAtPath:path isDirectory:&isDir];
  BOOL isFile = !isDir && [fm fileExistsAtPath:path];
  BOOL canRead = [fm isReadableFileAtPath:path];
  NSNumber *size = attrs[NSFileSize] ?: @0;
  NSDate *mtime = attrs[NSFileModificationDate];
  double lastModified = mtime ? [mtime timeIntervalSince1970] * 1000.0 : 0.0;
  NSString *mimeType = @"";
  NSString *ext = [path pathExtension];
  if (ext.length) {
    CFStringRef uti = UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, (__bridge CFStringRef)ext, NULL);
    if (uti) {
      CFStringRef mime = UTTypeCopyPreferredTagWithClass(uti, kUTTagClassMIMEType);
      if (mime) {
        mimeType = (__bridge_transfer NSString *)mime;
      }
      CFRelease(uti);
    }
  }
  return @{
    @"name": [path lastPathComponent],
    @"path": path,
    @"isDirectory": @(isDir),
    @"isFile": @(isFile),
    @"lastModified": @(lastModified),
    @"canRead": @(canRead),
    @"data": @"",
    @"mimeType": mimeType,
    @"size": size,
  };
}

static NSData *DataForEncoding(NSString *data, NSString *encoding) {
  if ([encoding isEqualToString:@"base64"]) {
    return [[NSData alloc] initWithBase64EncodedString:data options:0];
  }
  return [data dataUsingEncoding:NSUTF8StringEncoding];
}

static NSString *StringForData(NSData *data, NSString *encoding) {
  if ([encoding isEqualToString:@"base64"]) {
    return [data base64EncodedStringWithOptions:0];
  }
  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

// ---------- gzip（gzip 格式，与 Android GZIPOutputStream 兼容） ----------
static NSData *GzipData(NSData *input) {
  if (input.length == 0) return input;
  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  if (deflateInit2_(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, (int)sizeof(strm)) != Z_OK) {
    return nil;
  }
  uLong bound = deflateBound(&strm, (uLong)input.length);
  NSMutableData *out = [NSMutableData dataWithLength:bound];
  strm.next_in = (Bytef *)input.bytes;
  strm.avail_in = (uInt)input.length;
  strm.next_out = out.mutableBytes;
  strm.avail_out = (uInt)bound;
  int ret = deflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    deflateEnd(&strm);
    return nil;
  }
  [out setLength:strm.total_out];
  deflateEnd(&strm);
  return out;
}

static NSData *UnGzipData(NSData *input) {
  if (input.length == 0) return input;
  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  // 15 + 32：自动识别 gzip/zlib 头
  if (inflateInit2_(&strm, 15 + 32, ZLIB_VERSION, (int)sizeof(strm)) != Z_OK) {
    return nil;
  }
  NSMutableData *out = [NSMutableData data];
  Bytef buf[65536];
  strm.next_in = (Bytef *)input.bytes;
  strm.avail_in = (uInt)input.length;
  int ret;
  do {
    strm.next_out = buf;
    strm.avail_out = sizeof(buf);
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) {
      inflateEnd(&strm);
      return nil;
    }
    [out appendBytes:buf length:(sizeof(buf) - strm.avail_out)];
  } while (ret != Z_STREAM_END);
  inflateEnd(&strm);
  return out;
}

// ---------- hash ----------
static NSString *HexDigest(const unsigned char *digest, size_t len) {
  const char hex[] = "0123456789abcdef";
  NSMutableString *s = [NSMutableString stringWithCapacity:len * 2];
  for (size_t i = 0; i < len; i++) {
    [s appendFormat:@"%c%c", hex[digest[i] >> 4], hex[digest[i] & 0xF]];
  }
  return s;
}

static NSString *HashData(NSData *data, NSString *algorithm) {
  unsigned char digest[CC_SHA512_DIGEST_LENGTH] = {0};
  size_t len = CC_MD5_DIGEST_LENGTH;
  if ([algorithm isEqualToString:@"md5"]) {
    CC_MD5(data.bytes, (CC_LONG)data.length, digest);
  } else if ([algorithm isEqualToString:@"sha1"]) {
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    len = CC_SHA1_DIGEST_LENGTH;
  } else if ([algorithm isEqualToString:@"sha224"]) {
    CC_SHA224(data.bytes, (CC_LONG)data.length, digest);
    len = CC_SHA224_DIGEST_LENGTH;
  } else if ([algorithm isEqualToString:@"sha256"]) {
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    len = CC_SHA256_DIGEST_LENGTH;
  } else if ([algorithm isEqualToString:@"sha384"]) {
    CC_SHA384(data.bytes, (CC_LONG)data.length, digest);
    len = CC_SHA384_DIGEST_LENGTH;
  } else if ([algorithm isEqualToString:@"sha512"]) {
    CC_SHA512(data.bytes, (CC_LONG)data.length, digest);
    len = CC_SHA512_DIGEST_LENGTH;
  }
  return HexDigest(digest, len);
}

// ---------- 模块方法 ----------
RCT_EXPORT_METHOD(cp:(NSString *)source target:(NSString *)target resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  if ([[NSFileManager defaultManager] removeItemAtPath:target error:nil]) {}
  if (![[NSFileManager defaultManager] copyItemAtPath:source toPath:target error:&err]) {
    reject(@"copy_error", err.localizedDescription ?: @"copy failed", err);
    return;
  }
  resolve(nil);
}

RCT_EXPORT_METHOD(exists:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve(@([[NSFileManager defaultManager] fileExistsAtPath:path]));
}

RCT_EXPORT_METHOD(ls:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:path error:&err];
  if (names == nil) {
    reject(@"ls_error", err.localizedDescription ?: @"ls failed", err);
    return;
  }
  NSMutableArray *result = [NSMutableArray arrayWithCapacity:names.count];
  for (NSString *name in names) {
    NSString *p = [path stringByAppendingPathComponent:name];
    [result addObject:FileTypeDict(p, fm)];
  }
  resolve(result);
}

RCT_EXPORT_METHOD(mkdir:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path]) {
    if (![fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&err]) {
      reject(@"mkdir_error", err.localizedDescription ?: @"mkdir failed", err);
      return;
    }
  }
  resolve(FileTypeDict(path, fm));
}

RCT_EXPORT_METHOD(mv:(NSString *)source target:(NSString *)target resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:source]) {
    resolve(@NO);
    return;
  }
  [fm removeItemAtPath:target error:nil];
  if (![fm moveItemAtPath:source toPath:target error:&err]) {
    reject(@"mv_error", err.localizedDescription ?: @"mv failed", err);
    return;
  }
  resolve(@YES);
}

RCT_EXPORT_METHOD(rename:(NSString *)source name:(NSString *)name resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *target = [[source stringByDeletingLastPathComponent] stringByAppendingPathComponent:name];
  if (![fm fileExistsAtPath:source]) {
    resolve(@NO);
    return;
  }
  [fm removeItemAtPath:target error:nil];
  if (![fm moveItemAtPath:source toPath:target error:&err]) {
    reject(@"rename_error", err.localizedDescription ?: @"rename failed", err);
    return;
  }
  resolve(@YES);
}

RCT_EXPORT_METHOD(readFile:(NSString *)path encoding:(NSString *)encoding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&err];
  if (data == nil) {
    reject(@"read_error", err.localizedDescription ?: @"read failed", err);
    return;
  }
  NSString *str = StringForData(data, encoding ?: @"utf8");
  if (str == nil && ![(encoding ?: @"utf8") isEqualToString:@"base64"]) {
    reject(@"read_error", @"failed to decode utf8", nil);
    return;
  }
  resolve(str);
}

RCT_EXPORT_METHOD(stat:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path]) {
    reject(@"stat_error", @"path does not exist", nil);
    return;
  }
  resolve(FileTypeDict(path, fm));
}

RCT_EXPORT_METHOD(unlink:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path]) {
    resolve(@YES);
    return;
  }
  if (![fm removeItemAtPath:path error:&err]) {
    reject(@"unlink_error", err.localizedDescription ?: @"unlink failed", err);
    return;
  }
  resolve(@YES);
}

RCT_EXPORT_METHOD(writeFile:(NSString *)path data:(NSString *)data encoding:(NSString *)encoding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSData *raw = DataForEncoding(data, encoding ?: @"utf8");
  if (raw == nil) {
    reject(@"write_error", @"failed to encode data", nil);
    return;
  }
  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *dir = PathDir(path);
  if (![fm fileExistsAtPath:dir]) {
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
  }
  if (![raw writeToFile:path options:NSDataWritingAtomic error:&err]) {
    reject(@"write_error", err.localizedDescription ?: @"write failed", err);
    return;
  }
  resolve(nil);
}

RCT_EXPORT_METHOD(appendFile:(NSString *)path data:(NSString *)data encoding:(NSString *)encoding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSData *raw = DataForEncoding(data, encoding ?: @"utf8");
  if (raw == nil) {
    reject(@"append_error", @"failed to encode data", nil);
    return;
  }
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path]) {
    NSData *w = raw;
    if (![w writeToFile:path options:NSDataWritingAtomic error:&err]) {
      reject(@"append_error", err.localizedDescription ?: @"append failed", err);
      return;
    }
    resolve(nil);
    return;
  }
  NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
  if (fh == nil) {
    reject(@"append_error", @"can not open file for writing", nil);
    return;
  }
  @try {
    [fh seekToEndOfFile];
    [fh writeData:raw];
    [fh closeFile];
  } @catch (NSException *e) {
    reject(@"append_error", e.reason ?: @"append failed", nil);
    return;
  }
  resolve(nil);
}

RCT_EXPORT_METHOD(gzipFile:(NSString *)source target:(NSString *)target resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSData *input = [NSData dataWithContentsOfFile:source options:NSDataReadingMappedIfSafe error:&err];
  if (input == nil) {
    reject(@"gzip_error", err.localizedDescription ?: @"read failed", err);
    return;
  }
  NSData *gz = GzipData(input);
  if (gz == nil) {
    reject(@"gzip_error", @"gzip failed", nil);
    return;
  }
  [gz writeToFile:target options:NSDataWritingAtomic error:&err];
  if (err) {
    reject(@"gzip_error", err.localizedDescription, err);
    return;
  }
  resolve(nil);
}

RCT_EXPORT_METHOD(unGzipFile:(NSString *)source target:(NSString *)target resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSData *input = [NSData dataWithContentsOfFile:source options:NSDataReadingMappedIfSafe error:&err];
  if (input == nil) {
    reject(@"ungzip_error", err.localizedDescription ?: @"read failed", err);
    return;
  }
  NSData *raw = UnGzipData(input);
  if (raw == nil) {
    reject(@"ungzip_error", @"ungzip failed", nil);
    return;
  }
  [raw writeToFile:target options:NSDataWritingAtomic error:&err];
  if (err) {
    reject(@"ungzip_error", err.localizedDescription, err);
    return;
  }
  resolve(nil);
}

RCT_EXPORT_METHOD(gzipString:(NSString *)data encoding:(NSString *)encoding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSData *input = DataForEncoding(data, encoding ?: @"utf8");
  if (input == nil) {
    reject(@"gzip_error", @"failed to encode data", nil);
    return;
  }
  NSData *gz = GzipData(input);
  if (gz == nil) {
    reject(@"gzip_error", @"gzip failed", nil);
    return;
  }
  resolve([gz base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(unGzipString:(NSString *)data encoding:(NSString *)encoding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSData *input = [[NSData alloc] initWithBase64EncodedString:data options:0];
  if (input == nil) {
    reject(@"ungzip_error", @"invalid base64", nil);
    return;
  }
  NSData *raw = UnGzipData(input);
  if (raw == nil) {
    reject(@"ungzip_error", @"ungzip failed", nil);
    return;
  }
  NSString *str = StringForData(raw, encoding ?: @"utf8");
  if (str == nil) {
    reject(@"ungzip_error", @"failed to decode utf8", nil);
    return;
  }
  resolve(str);
}

RCT_EXPORT_METHOD(hash:(NSString *)path algorithm:(NSString *)algorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSError *err = nil;
  NSData *input = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&err];
  if (input == nil) {
    reject(@"hash_error", err.localizedDescription ?: @"read failed", err);
    return;
  }
  resolve(HashData(input, algorithm ?: @"md5"));
}

@end