#!/bin/bash
tmp_obj=/tmp/bluetooth.o
OBJ=/home/lb/Documents/backup/andrsource/out/target/product/hammerhead/obj/
SRC=/home/lb/Documents/backup/andrsource
llc --mtriple=thumbv7--linux-androideabi $1 --filetype=obj --relocation-model=pic --thread-model=posix --asm-verbose --mcpu=krait --mattr=+soft-float,+neon -target-abi aapcs-linux --function-sections --data-sections -I $SRC/system/core/include -I $SRC/system/media/audio/include -I $SRC/hardware/libhardware/include -I $SRC/hardware/libhardware_legacy/include -I $SRC/hardware/ril/include -I $SRC/libnativehelper/include -I $SRC/frameworks/native/include -I $SRC/frameworks/native/opengl/include -I $SRC/frameworks/av/include -I $SRC/frameworks/base/include -I $SRC/out/target/product/hammerhead/obj/include -I $SRC/device/lge/hammerhead/kernel-headers -I $SRC/hardware/qcom/msm8x74/kernel-headers -I $SRC/bionic/libc/arch-arm/include -I $SRC/bionic/libc/include -I $SRC/bionic/libc/kernel/uapi -I $SRC/bionic/libc/kernel/uapi/asm-arm -I $SRC/bionic/libm/include -I $SRC/bionic/libm/include/arm -I $SRC/system/bt/btcore/include -I $SRC/system/bt/gki/common -I $SRC/system/bt/gki/ulinux -I $SRC/system/bt/osi/include -I $SRC/device/lge/hammerhead/bluetooth -I $SRC/external/libcxx/include -I $SRC/libnativehelper/include/nativehelper -I $SRC/build/core/combo/include/arch/linux-arm -I $SRC/external/tinyxml2 -I $SRC/external/zlib -O0 --stackrealign -o $tmp_obj
$SRC/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/arm-linux-androideabi/bin/ld -X --eh-frame-hdr -m armelf_linux_eabi -shared -dynamic-linker /system/bin/linker -o $2 -L$OBJ/lib -L$SRC/prebuilts/clang/linux-x86/host/3.6/lib -L/lib -L/usr/lib -soname bluetooth.default.so --gc-sections $tmp_obj $OBJ/lib/crtbegin_so.o --whole-archive $OBJ/STATIC_LIBRARIES/libbt-brcm_gki_intermediates/libbt-brcm_gki.a $OBJ/STATIC_LIBRARIES/libbtcore_intermediates/libbtcore.a $OBJ/STATIC_LIBRARIES/libosi_intermediates/libosi.a --no-whole-archive $OBJ/STATIC_LIBRARIES/libtinyxml2_intermediates/libtinyxml2.a $OBJ/STATIC_LIBRARIES/libunwind_llvm_intermediates/libunwind_llvm.a $OBJ/STATIC_LIBRARIES/libcompiler_rt-extras_intermediates/libcompiler_rt-extras.a $SRC/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/arm-linux-androideabi/lib/libatomic.a $SRC/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/lib/gcc/arm-linux-androideabi/4.9.x-google/libgcc.a -lcutils -ldl -llog -lpower -lz -lc++ -ldl -lc -lm -z noexecstack -z relro -z now --build-id=md5 --warn-shared-textrel --fatal-warnings --icf=safe --hash-style=gnu --no-fix-cortex-a8 --exclude-libs libunwind_llvm.a --no-undefined $OBJ/lib/crtend_so.o -Bsymbolic -Bsymbolic-functions