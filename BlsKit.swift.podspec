Pod::Spec.new do |s|
  s.name             = 'BlsKit.swift'
  s.module_name      = 'BlsKit'
  s.version          = '1.0'
  s.summary          = 'BLS verification crypto library for Swift'

  s.description      = <<-DESC
BlsKit includes crypto verification function that can be used in pure Swift. It uses c++ code from https://github.com/Chia-Network/bls-signatures.
                       DESC

  s.homepage         = 'https://github.com/horizontalsystems/bls-kit-ios'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Horizontal Systems' => 'hsdao@protonmail.ch' }
  s.source           = { git: 'https://github.com/horizontalsystems/bls-kit-ios.git', tag: "#{s.version}" }
  s.social_media_url = 'http://horizontalsystems.io/'

  s.ios.deployment_target = '11.0'
  s.swift_version = '5'

  s.source_files = 'BlsKit/Classes/**/*'

  s.libraries = 'c++'
  s.requires_arc = true

  s.preserve_paths = ['BlsKit/Libraries']
  s.vendored_libraries  = ['BlsKit/Libraries/lib/libbls.a']

  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/BlsKit/Libraries/include" "${PODS_TARGET_SRCROOT}/BlsKit/Libraries/include/relic"',
    'LIBRARY_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/BlsKit/Libraries/lib"'
  }
end
