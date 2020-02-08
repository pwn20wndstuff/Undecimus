/*
 * OSSerializeBinary.h
 * Brandon Azad
 */
#ifndef OOB_TIMESTAMP__OSSERIALIZEBINARY__H_
#define OOB_TIMESTAMP__OSSERIALIZEBINARY__H_

enum {
	kOSSerializeDictionary      = 0x01000000,
	kOSSerializeArray           = 0x02000000,
	kOSSerializeSet             = 0x03000000,
	kOSSerializeNumber          = 0x04000000,
	kOSSerializeSymbol          = 0x08000000,
	kOSSerializeString          = 0x09000000,
	kOSSerializeData            = 0x0a000000,
	kOSSerializeBoolean         = 0x0b000000,
	kOSSerializeObject          = 0x0c000000,
	kOSSerializeTypeMask        = 0x7f000000,
	kOSSerializeDataMask        = 0x00ffffff,
	kOSSerializeEndCollecton    = 0x80000000,
	kOSSerializeBinarySignature = 0x000000d3,
};

#endif
