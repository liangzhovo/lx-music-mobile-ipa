# iOS native bridge for lx-music-mobile Android-only modules
# Implements UtilsModule / CacheModule / CryptoModule / LyricModule on iOS
Pod::Spec.new do |s|
  s.name         = 'RNModuleBridge'
  s.version      = '1.0.0'
  s.summary      = 'iOS native modules bridge for lx-music-mobile'
  s.homepage     = 'https://github.com/lyswhut/lx-music-mobile'
  s.license      = { :type => 'Apache-2.0' }
  s.author       = { 'lx-music-mobile' => 'dev@local' }
  s.platforms    = { :ios => '11.0' }
  s.source       = { :path => '.' }
  s.source_files = '*.{h,m}'
  s.frameworks   = 'Foundation', 'UIKit', 'Security', 'UserNotifications', 'CoreTelephony'
  s.libraries    = 'z'
  s.dependency 'React-Core'
end