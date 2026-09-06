#import "RNModules.h"
@import Foundation;
@import CommonCrypto;

@implementation CryptoModule

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
  return NO;
}

static NSData *Base64Decode(NSString *s) {
  return [[NSData alloc] initWithBase64EncodedString:s options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

static NSString *Base64Encode(NSData *data) {
  return [data base64EncodedStringWithOptions:0];
}

static NSString *HexString(const unsigned char *bytes, size_t len) {
  const char hex[] = "0123456789abcdef";
  NSMutableString *s = [NSMutableString stringWithCapacity:len * 2];
  for (size_t i = 0; i < len; i++) {
    [s appendFormat:@"%c%c", hex[bytes[i] >> 4], hex[bytes[i] & 0xF]];
  }
  return s;
}

// ---------- RSA（iOS 暂不支持：Security.framework 头在本编译环境不可见，接口保留避免 JS 崩溃） ----------

static NSError *RSAUnavailableError(void) {
  return [NSError errorWithDomain:@"Crypto" code:99 userInfo:@{NSLocalizedDescriptionKey: @"RSA is not available on iOS yet"}];
}

RCT_EXPORT_METHOD(generateRsaKey:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  reject(@"rsa_unavailable", @"RSA is not available on iOS yet", RSAUnavailableError());
}

RCT_EXPORT_METHOD(rsaEncrypt:(NSString *)text key:(NSString *)key padding:(NSString *)padding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  reject(@"rsa_unavailable", @"RSA is not available on iOS yet", RSAUnavailableError());
}

RCT_EXPORT_METHOD(rsaDecrypt:(NSString *)text key:(NSString *)key padding:(NSString *)padding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  reject(@"rsa_unavailable", @"RSA is not available on iOS yet", RSAUnavailableError());
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(rsaEncryptSync:(NSString *)text key:(NSString *)key padding:(NSString *)padding)
{
  return @"";
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(rsaDecryptSync:(NSString *)text key:(NSString *)key padding:(NSString *)padding)
{
  return @"";
}

// ---------- AES ----------

- (NSString *)cryptAES:(NSString *)text key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode encrypt:(BOOL)encrypt withError:(NSError **)errorOut {
  NSData *textBytes = Base64Decode(text);
  NSData *keyBytes = Base64Decode(key);
  BOOL isECB = [mode containsString:@"ECB"] || iv.length == 0;
  BOOL noPadding = [mode containsString:@"NoPadding"];
  NSData *ivBytes = iv.length ? Base64Decode(iv) : [NSData data];

  CCCryptorStatus status;
  size_t outLen = 0;
  size_t blockSize = textBytes.length + kCCBlockSizeAES128;
  NSMutableData *outData = [NSMutableData dataWithLength:blockSize];
  uint32_t options = isECB ? kCCOptionECBMode : 0;
  if (!noPadding) options |= kCCOptionPKCS7Padding;
  if (isECB) {
    status = CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt,
                     kCCAlgorithmAES128,
                     options,
                     keyBytes.bytes, kCCKeySizeAES128,
                     NULL,
                     textBytes.bytes, textBytes.length,
                     outData.mutableBytes, outData.length, &outLen);
  } else {
    uint8_t fullIv[16] = {0};
    [ivBytes getBytes:fullIv length:MIN(ivBytes.length, 16)];
    status = CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt,
                     kCCAlgorithmAES128,
                     kCCOptionPKCS7Padding,
                     keyBytes.bytes, kCCKeySizeAES128,
                     fullIv,
                     textBytes.bytes, textBytes.length,
                     outData.mutableBytes, outData.length, &outLen);
  }
  if (status != kCCSuccess) {
    if (errorOut) *errorOut = [NSError errorWithDomain:@"Crypto" code:5 userInfo:@{NSLocalizedDescriptionKey: @"aes crypt failed"}];
    return nil;
  }
  [outData setLength:outLen];
  if (encrypt) {
    return Base64Encode(outData);
  }
  return [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding] ?: @"";
}

- (void)handleAES:(NSString *)method text:(NSString *)text key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode encrypt:(BOOL)encrypt resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
  NSError *err = nil;
  NSString *r = [self cryptAES:text key:key iv:iv mode:mode encrypt:encrypt withError:&err];
  if (err) {
    reject(@"aes_error", err.localizedDescription, err);
    return;
  }
  resolve(r);
}

RCT_EXPORT_METHOD(aesEncrypt:(NSString *)text key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self handleAES:@"aesEncrypt" text:text key:key iv:iv mode:mode encrypt:YES resolver:resolve rejecter:reject];
}

RCT_EXPORT_METHOD(aesDecrypt:(NSString *)text key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self handleAES:@"aesDecrypt" text:text key:key iv:iv mode:mode encrypt:NO resolver:resolve rejecter:reject];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(aesEncryptSync:(NSString *)text key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode)
{
  NSError *err = nil;
  return [self cryptAES:text key:key iv:iv mode:mode encrypt:YES withError:&err] ?: @"";
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(aesDecryptSync:(NSString *)text key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode)
{
  NSError *err = nil;
  return [self cryptAES:text key:key iv:iv mode:mode encrypt:NO withError:&err] ?: @"";
}

RCT_EXPORT_METHOD(sha1:(NSString *)input resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
  unsigned char digest[CC_SHA1_DIGEST_LENGTH];
  CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
  resolve(HexString(digest, CC_SHA1_DIGEST_LENGTH));
}

@end

@implementation LyricModule

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
  return NO;
}

// 桌面歌词是 Android 悬浮窗特性，iOS 无此能力；提供空实现防止 NativeModules.LyricModule 缺失崩溃
- (void)noopResolver:(RCTPromiseResolveBlock)resolve {
  resolve(nil);
}

RCT_EXPORT_METHOD(setSendLyricTextEvent:(BOOL)isSend resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(showDesktopLyric:(NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(hideDesktopLyric:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(play:(double)time resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(pause:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setLyric:(NSString *)lyric translation:(NSString *)translation roma:(NSString *)roma resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setPlaybackRate:(double)rate resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(toggleTranslation:(BOOL)show resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(toggleRoma:(BOOL)show resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(toggleLock:(BOOL)lock resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setColor:(NSString *)unplay played:(NSString *)played shadow:(NSString *)shadow resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setAlpha:(double)alpha resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setTextSize:(double)size resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setShowToggleAnima:(BOOL)show resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setSingleLine:(BOOL)single resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setPosition:(double)x y:(double)y resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setMaxLineNum:(double)num resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setWidth:(double)width resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(setLyricTextPosition:(NSString *)x y:(NSString *)y resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }
RCT_EXPORT_METHOD(checkOverlayPermission:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { resolve(@NO); }
RCT_EXPORT_METHOD(openOverlayPermissionActivity:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) { [self noopResolver:resolve]; }

@end