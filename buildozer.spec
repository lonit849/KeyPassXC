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
android.api = 33
android.minapi = 21
android.ndk = 25b
android.sdk = 33
android.archs = arm64-v8a,armeabi-v7a
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
