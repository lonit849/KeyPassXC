[app]
title = KeyPassXC
package.name = keypassxc
package.domain = org.keypassxc
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,txt,json
version = 0.1
requirements = python3,kivy==2.3.0,cryptography
orientation = portrait
fullscreen = 0
android.api = 34
android.minapi = 21
android.ndk = 28c
android.sdk = 34
android.accept_sdk_license = True
android.archs = arm64-v8a,armeabi-v7a
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
