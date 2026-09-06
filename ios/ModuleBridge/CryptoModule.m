#import "RNModules.h"
@import Security;
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

// ---------- RSA（使用全版本可用的 SecKeyGeneratePair / SecKeyRawEncrypt / SecKeyRawDecrypt） ----------

static SecKeyRef KeyFromDERData(NSData *der, BOOL isPublic) {
  NSDictionary *attrs = @{
    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
    (__bridge id)kSecAttrKeyClass: isPublic ? (__bridge id)kSecAttrKeyClassPublic : (__bridge id)kSecAttrKeyClassPrivate,
  };
  SecKeyRef key = NULL;
  SecItemImport((__bridge CFDataRef)der, NULL, NULL, NULL, 0, NULL, (__bridge CFDictionaryRef)attrs, (CFTypeRef *)&key);
  if (key) {
    return key;
  }
  // 兜底：SecItemImport 失败时尝试 X509/PKCS8 解析
  return SecKeyCreateWithData((__bridge CFDataRef)der, (__bridge CFDictionaryRef)attrs, NULL);
}

static NSData *RsaCrypt(NSData *input, SecKeyRef key, BOOL encrypt, BOOL noPadding) {
  SecPadding padding = noPadding ? kSecPaddingNone : kSecPaddingPKCS1;
  if (encrypt) {
    size_t bufLen = SecKeyGetBlockSize(key);
    NSMutableData *out = [NSMutableData dataWithLength:bufLen];
    OSStatus status = SecKeyRawEncrypt(key, padding, input.bytes, input.length, out.mutableBytes, &bufLen);
    if (status != errSecSuccess) return nil;
    [out setLength:bufLen];
    return out;
  } else {
    size_t bufLen = SecKeyGetBlockSize(key);
    NSMutableData *out = [NSMutableData dataWithLength:bufLen];
    OSStatus status = SecKeyRawDecrypt(key, padding, input.bytes, input.length, out.mutableBytes, &bufLen);
    if (status != errSecSuccess) return nil;
    [out setLength:bufLen];
    return out;
  }
}

- (NSDictionary *)cryptRSA:(NSString *)text key:(NSString *)key padding:(NSString *)padding encrypt:(BOOL)encrypt withError:(NSError **)errorOut {
  NSData *keyBytes = Base64Decode([key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]);
  if (!keyBytes.length) {
    if (errorOut) *errorOut = [NSError errorWithDomain:@"Crypto" code:1 userInfo:@{NSLocalizedDescriptionKey: @"invalid key"}];
    return nil;
  }
  BOOL isPublic = encrypt;
  BOOL noPadding = [padding containsString:@"NoPadding"];
  SecKeyRef secKey = KeyFromDERData(keyBytes, isPublic);
  if (!secKey) {
    if (errorOut) *errorOut = [NSError errorWithDomain:@"Crypto" code:2 userInfo:@{NSLocalizedDescriptionKey: @"invalid key DER"}];
    return nil;
  }
  NSData *input = encrypt ? [text dataUsingEncoding:NSUTF8StringEncoding] : Base64Decode(text);
  if (!input.length) {
    CFRelease(secKey);
    if (errorOut) *errorOut = [NSError errorWithDomain:@"Crypto" code:3 userInfo:@{NSLocalizedDescriptionKey: @"empty input"}];
    return nil;
  }
  NSData *output = RsaCrypt(input, secKey, encrypt, noPadding);
  CFRelease(secKey);
  if (!output) {
    if (errorOut) *errorOut = [NSError errorWithDomain:@"Crypto" code:4 userInfo:@{NSLocalizedDescriptionKey: @"crypt failed"}];
    return nil;
  }
  if (encrypt) {
    return @{ @"result": Base64Encode(output) };
  }
  NSString *str = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding];
  return @{ @"result": str ?: @"" };
}

RCT_EXPORT_METHOD(generateRsaKey:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSDictionary *attrs = @{
    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
    (__bridge id)kSecAttrKeySizeInBits: @2048,
    (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
  };
  SecKeyRef privateKey = NULL;
  OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)attrs, &privateKey, NULL);
  if (status != errSecSuccess || !privateKey) {
    reject(@"rsa_key_error", @"generate key failed", nil);
    return;
  }
  SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
  NSData *pubDer = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, NULL) ?: [NSData data];
  NSData *privDer = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(privateKey, NULL) ?: [NSData data];
  if (publicKey) CFRelease(publicKey);
  CFRelease(privateKey);
  resolve(@{
    @"publicKey": Base64Encode(pubDer),
    @"privateKey": Base64Encode(privDer),
  });
}

- (void)handleRSA:(NSString *)method text:(NSString *)text key:(NSString *)key padding:(NSString *)padding encrypt:(BOOL)encrypt resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
  NSError *err = nil;
  NSDictionary *r = [self cryptRSA:text key:key padding:padding encrypt:encrypt withError:&err];
  if (err) {
    reject(@"rsa_error", err.localizedDescription, err);
    return;
  }
  resolve(r[@"result"]);
}

RCT_EXPORT_METHOD(rsaEncrypt:(NSString *)text key:(NSString *)key padding:(NSString *)padding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self handleRSA:@"rsaEncrypt" text:text key:key padding:padding encrypt:YES resolver:resolve rejecter:reject];
}

RCT_EXPORT_METHOD(rsaDecrypt:(NSString *)text key:(NSString *)key padding:(NSString *)padding resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self handleRSA:@"rsaDecrypt" text:text key:key padding:padding encrypt:NO resolver:resolve rejecter:reject];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(rsaEncryptSync:(NSString *)text key:(NSString *)key padding:(NSString *)padding)
{
  NSError *err = nil;
  NSDictionary *r = [self cryptRSA:text key:key padding:padding encrypt:YES withError:&err];
  return r ? r[@"result"] : @"";
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(rsaDecryptSync:(NSString *)text key:(NSString *)key padding:(NSString *)padding)
{
  NSError *err = nil;
  NSDictionary *r = [self cryptRSA:text key:key padding:padding encrypt:NO withError:&err];
  return r ? r[@"result"] : @"";
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