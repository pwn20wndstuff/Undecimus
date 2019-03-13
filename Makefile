TARGET = Undecimus

.PHONY: all clean

all: clean
	xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PRODUCT_BUNDLE_IDENTIFIER="science.xnu.undecimus" -sdk iphoneos -configuration Debug -quiet
	ln -sf build/Debug-iphoneos Payload
	ldid -SUndecimus/multi_path.entitlements Payload/$(TARGET).app/$(TARGET)
	zip -r9 $(TARGET).ipa Payload/$(TARGET).app -q
	if ! [ -e $(TARGET).ipa ]; then echo $(TARGET).ipa does not exist!; exit 1; fi;

clean:
	rm -rf build Payload $(TARGET).ipa
