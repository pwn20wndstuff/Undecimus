TARGET = Undecimus

.PHONY: all clean

all:
	xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -sdk iphoneos
	ln -sf build/Release-iphoneos Payload
	# strip Payload/$(TARGET).app/$(TARGET)
	zip -r9 $(TARGET).ipa Payload/$(TARGET).app

clean:
	rm -rf build Payload $(TARGET).ipa
