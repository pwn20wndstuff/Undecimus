TARGET = Undecimus

.PHONY: all clean

all: clean
	xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PRODUCT_BUNDLE_IDENTIFIER="science.xnu.undecimus" -sdk iphoneos -configuration Debug -arch arm64 -arch arm64e
	ln -sf build/Debug-iphoneos Payload
	# strip Payload/$(TARGET).app/$(TARGET)
	ldid -SUndecimus/resources/multi_path.entitlements Payload/$(TARGET).app/$(TARGET)
	zip -r9 $(TARGET).ipa Payload/$(TARGET).app

clean:
	rm -rf build Payload $(TARGET).ipa
