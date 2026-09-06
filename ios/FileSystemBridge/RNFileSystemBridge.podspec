# iOS implementation bridge for react-native-file-system
# (the upstream fork used by lx-music-mobile lacks the ios/ source dir,
#  this local pod provides the FileSystemModule native implementation)
Pod::Spec.new do |s|
  s.name         = 'RNFileSystemBridge'
  s.version      = '1.0.0'
  s.summary      = 'iOS FileSystemModule bridge for react-native-file-system'
  s.homepage     = 'https://github.com/lyswhut/lx-music-mobile'
  s.license      = { :type => 'Apache-2.0' }
  s.author       = { 'lx-music-mobile' => 'dev@local' }
  s.platforms    = { :ios => '11.0' }
  s.source       = { :path => '.' }
  s.source_files = 'FileSystemModule.{h,m}'
  s.frameworks   = 'Foundation'
  s.libraries    = 'z'
  s.dependency 'React-Core'
  # 修复系统框架头在模块模式下被 -Werror=non-modular-include 拦断的问题
  s.xcconfig     = { 'OTHER_CFLAGS' => '-Wno-non-modular-include-in-framework-module' }
end