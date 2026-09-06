#import "RNModules.h"
#import <UIKit/UIKit.h>
#import <UserNotifications/UserNotifications.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <React/RCTUtils.h>

@implementation UtilsModule

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
  return NO;
}

static UIViewController *TopViewController(void) {
  UIViewController *top = RCTKeyWindow().rootViewController;
  while (top.presentedViewController) {
    top = top.presentedViewController;
  }
  return top;
}

// 退出应用（侧载场景；iOS 规范不鼓励自退出，但自签无审核限制）
RCT_EXPORT_METHOD(exitApp)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    exit(0);
  });
}

// Android ABI 概念，iOS 返回空
RCT_EXPORT_METHOD(getSupportedAbis:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve(@[]);
}

// Android 专属，iOS 空实现
RCT_EXPORT_METHOD(installApk:(NSString *)filePath fileProviderAuthority:(NSString *)authority resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve(nil);
}

RCT_EXPORT_METHOD(screenkeepAwake)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    [UIApplication sharedApplication].idleTimerDisabled = YES;
  });
}

RCT_EXPORT_METHOD(screenUnkeepAwake)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    [UIApplication sharedApplication].idleTimerDisabled = NO;
  });
}

RCT_EXPORT_METHOD(getWIFIIPV4Address:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSString *address = @"";
  struct ifaddrs *interfaces = NULL;
  if (getifaddrs(&interfaces) == 0) {
    struct ifaddrs *temp = interfaces;
    while (temp) {
      if (temp->ifa_addr && temp->ifa_addr->sa_family == AF_INET &&
          (temp->ifa_flags & IFF_UP) && !(temp->ifa_flags & IFF_LOOPBACK)) {
        NSString *name = [NSString stringWithUTF8String:temp->ifa_name];
        if ([name hasPrefix:@"en"]) {
          address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp->ifa_addr)->sin_addr)];
          break;
        }
      }
      temp = temp->ifa_next;
    }
    freeifaddrs(interfaces);
  }
  resolve(address);
}

RCT_EXPORT_METHOD(getDeviceName:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve([[UIDevice currentDevice] name] ?: @"iPhone");
}

RCT_EXPORT_METHOD(isNotificationsEnabled:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  if (@available(iOS 10.0, *)) {
    [[UNUserNotificationCenter currentNotificationCenter] getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
      resolve(@(settings.authorizationStatus == UNAuthorizationStatusAuthorized || settings.authorizationStatus == UNAuthorizationStatusProvisional));
    }];
  } else {
    resolve(@NO);
  }
}

RCT_EXPORT_METHOD(requestNotificationPermission:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  if (@available(iOS 10.0, *)) {
    [[UNUserNotificationCenter currentNotificationCenter] requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound | UNAuthorizationOptionBadge)
                                                                        completionHandler:^(BOOL granted, NSError *error) {
      if (error) {
        reject(@"notification_error", error.localizedDescription, error);
      } else {
        resolve(@(granted));
      }
    }];
  } else {
    resolve(@NO);
  }
}

RCT_EXPORT_METHOD(openNotificationPermissionActivity:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self requestNotificationPermission:resolve rejecter:reject];
}

RCT_EXPORT_METHOD(shareText:(NSString *)shareTitle title:(NSString *)title text:(NSString *)text resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:@[text] applicationActivities:nil];
    vc.popoverPresentationController.sourceView = RCTKeyWindow();
    vc.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(RCTKeyWindow().bounds), CGRectGetMidY(RCTKeyWindow().bounds), 0, 0);
    [TopViewController() presentViewController:vc animated:YES completion:^{
      resolve(nil);
    }];
  });
}

RCT_EXPORT_METHOD(getSystemLocales:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSArray<NSString *> *langs = [NSLocale preferredLanguages];
  resolve(langs.count ? langs[0] : @"en");
}

RCT_EXPORT_METHOD(getWindowSize:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    CGRect bounds = RCTKeyWindow().bounds;
    resolve(@{ @"width": @(bounds.size.width), @"height": @(bounds.size.height) });
  });
}

// iOS 事件监听占位（屏幕常亮状态/窗口尺寸事件在 iOS 无常驻监听需求）
RCT_EXPORT_METHOD(listenWindowSizeChanged)
{
}

RCT_EXPORT_METHOD(isIgnoringBatteryOptimization:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve(@NO);
}

RCT_EXPORT_METHOD(requestIgnoreBatteryOptimization:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve(@YES);
}

@end

@implementation CacheModule

RCT_EXPORT_MODULE()

static NSString *CacheDirPath(void) {
  NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
  return [paths firstObject] ?: NSTemporaryDirectory();
}

static unsigned long long DirSize(NSString *path) {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray<NSString *> *files = [fm subpathsOfDirectoryAtPath:path error:nil] ?: @[];
  unsigned long long total = 0;
  for (NSString *f in files) {
    NSString *full = [path stringByAppendingPathComponent:f];
    NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
    total += [attrs[NSFileSize] unsignedLongLongValue];
  }
  return total;
}

RCT_EXPORT_METHOD(getAppCacheSize:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  resolve(@(DirSize(CacheDirPath())));
}

RCT_EXPORT_METHOD(clearAppCache:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:CacheDirPath() error:nil] ?: @[];
  for (NSString *name in names) {
    [fm removeItemAtPath:[CacheDirPath() stringByAppendingPathComponent:name] error:nil];
  }
  resolve(nil);
}

@end