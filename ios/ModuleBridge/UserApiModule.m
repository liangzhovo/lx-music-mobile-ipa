#import "UserApiModule.h"

// 用户音源脚本引擎（Android 用脚本引擎执行音源 JS）。
// iOS 占位实现：模块存在、方法空实现，保证 app 初始化与界面可用；
// 真正的 JavaScriptCore 脚本引擎 + 宿主 API（request/crypto 等）为后续工程。
@implementation UserApiModule

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
  return NO;
}

- (NSArray<NSString *> *)supportedEvents {
  return @[ @"api-action" ];
}

RCT_EXPORT_METHOD(loadScript:(NSDictionary *)info)
{
  // TODO: iOS 音源脚本引擎（JavaScriptCore）—— 后续实现
}

RCT_EXPORT_METHOD(sendAction:(NSString *)action data:(NSString *)data)
{
  // TODO: 向脚本引擎转发动作 —— 后续实现
}

RCT_EXPORT_METHOD(destroy)
{
  // TODO: 销毁引擎 —— 后续实现
}

@end