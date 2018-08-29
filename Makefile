THEOS=./theos
DEBUG=0
THEOS_DEVICE_IP=127.0.0.1
THEOS_DEVICE_PORT=2222

include $(THEOS)/makefiles/common.mk

stage::
	mkdir $(THEOS_STAGING_DIR)/Applications
	xcodebuild -arch arm64 -sdk iphoneos CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO OTHER_CFLAGS="-DWANT_CYDIA" OTHER_CPLUSPLUSFLAGS="-DWANT_CYDIA"
	strip ./build/Release-iphoneos/Rollectra.app/Rollectra
	ldid -Sentitlements.xml ./build/Release-iphoneos/Rollectra.app/Rollectra
	cp -r ./build/Release-iphoneos/Rollectra.app $(THEOS_STAGING_DIR)/Applications/Rollectra.app
	chmod 6755 $(THEOS_STAGING_DIR)/Applications/Rollectra.app/Rollectra

clean::
	rm -rf ./build

include $(THEOS_MAKE_PATH)/null.mk
