/*
 * libMobileGestalt header.
 * Mobile gestalt functions as a QA system. You ask it a question, and it gives you the answer! :)
 *
 * Copyright (c) 2013-2014 Cykey (David Murray)
 * All rights reserved.
 */

#ifndef LIBMOBILEGESTALT_H_
#define LIBMOBILEGESTALT_H_

#include <CoreFoundation/CoreFoundation.h>

#if __cplusplus
extern "C" {
#endif

#pragma mark - API

    CFPropertyListRef MGCopyAnswer(CFStringRef property);

    Boolean MGGetBoolAnswer(CFStringRef property);

    /*
     * Arguments are still a mistery.
     * CFPropertyListRef MGCopyAnswerWithError(CFStringRef question, int *error, ...);
     */

    /* Use 0 for __unknown0. */
    CFPropertyListRef MGCopyMultipleAnswers(CFArrayRef questions, int __unknown0);

    /*
     * Not all questions are assignable.
     * For example, kMGUserAssignedDeviceName is assignable but
     * kMGProductType is not.
     */
    int MGSetAnswer(CFStringRef question, CFTypeRef answer);

#pragma mark - Identifying Information

    static const CFStringRef kMGDiskUsage = CFSTR("DiskUsage");
    static const CFStringRef kMGModelNumber = CFSTR("ModelNumber");
    static const CFStringRef kMGSIMTrayStatus = CFSTR("SIMTrayStatus");
    static const CFStringRef kMGSerialNumber = CFSTR("SerialNumber");
    static const CFStringRef kMGMLBSerialNumber = CFSTR("MLBSerialNumber");
    static const CFStringRef kMGUniqueDeviceID = CFSTR("UniqueDeviceID");
    static const CFStringRef kMGUniqueDeviceIDData = CFSTR("UniqueDeviceIDData");
    static const CFStringRef kMGUniqueChipID = CFSTR("UniqueChipID");
    static const CFStringRef kMGInverseDeviceID = CFSTR("InverseDeviceID");
    static const CFStringRef kMGDiagnosticsData = CFSTR("DiagData");
    static const CFStringRef kMGDieID = CFSTR("DieId");
    static const CFStringRef kMGCPUArchitecture = CFSTR("CPUArchitecture");
    static const CFStringRef kMGPartitionType = CFSTR("PartitionType");
    static const CFStringRef kMGUserAssignedDeviceName = CFSTR("UserAssignedDeviceName");

#pragma mark - Bluetooth Information

    static const CFStringRef kMGBluetoothAddress = CFSTR("BluetoothAddress");

#pragma mark - Battery Information

    static const CFStringRef kMGRequiredBatteryLevelForSoftwareUpdate = CFSTR("RequiredBatteryLevelForSoftwareUpdate");
    static const CFStringRef kMGBatteryIsFullyCharged = CFSTR("BatteryIsFullyCharged");
    static const CFStringRef kMGBatteryIsCharging = CFSTR("BatteryIsCharging");
    static const CFStringRef kMGBatteryCurrentCapacity = CFSTR("BatteryCurrentCapacity");
    static const CFStringRef kMGExternalPowerSourceConnected = CFSTR("ExternalPowerSourceConnected");

#pragma mark - Baseband Information

static const CFStringRef kMGBasebandSerialNumber = CFSTR("BasebandSerialNumber");
    static const CFStringRef kMGBasebandCertId = CFSTR("BasebandCertId");
    static const CFStringRef kMGBasebandChipId = CFSTR("BasebandChipId");
    static const CFStringRef kMGBasebandFirmwareManifestData = CFSTR("BasebandFirmwareManifestData");
    static const CFStringRef kMGBasebandFirmwareVersion = CFSTR("BasebandFirmwareVersion");
    static const CFStringRef kMGBasebandKeyHashInformation = CFSTR("BasebandKeyHashInformation");

#pragma mark - Telephony Information

    static const CFStringRef kMGCarrierBundleInfo = CFSTR("CarrierBundleInfoArray");
    static const CFStringRef kMGCarrierInstallCapability = CFSTR("CarrierInstallCapability");
    static const CFStringRef kMGInternationalMobileEquipmentIdentity = CFSTR("InternationalMobileEquipmentIdentity");
    static const CFStringRef kMGMobileSubscriberCountryCode = CFSTR("MobileSubscriberCountryCode");
    static const CFStringRef kMGMobileSubscriberNetworkCode = CFSTR("MobileSubscriberNetworkCode");

#pragma mark - Device Information

    static const CFStringRef kMGChipID = CFSTR("ChipID");
    static const CFStringRef kMGComputerName = CFSTR("ComputerName");
    static const CFStringRef kMGDeviceVariant = CFSTR("DeviceVariant");
    static const CFStringRef kMGHWModel = CFSTR("HWModelStr");
    static const CFStringRef kMGBoardId = CFSTR("BoardId");
    static const CFStringRef kMGHardwarePlatform = CFSTR("HardwarePlatform");
    static const CFStringRef kMGDeviceName = CFSTR("DeviceName");
    static const CFStringRef kMGDeviceColor = CFSTR("DeviceColor");
    static const CFStringRef kMGDeviceClassNumber = CFSTR("DeviceClassNumber");
    static const CFStringRef kMGDeviceClass = CFSTR("DeviceClass");
    static const CFStringRef kMGBuildVersion = CFSTR("BuildVersion");
    static const CFStringRef kMGProductName = CFSTR("ProductName");
    static const CFStringRef kMGProductType = CFSTR("ProductType");
    static const CFStringRef kMGProductVersion = CFSTR("ProductVersion");
    static const CFStringRef kMGFirmwareNonce = CFSTR("FirmwareNonce");
    static const CFStringRef kMGFirmwareVersion = CFSTR("FirmwareVersion");
    static const CFStringRef kMGFirmwarePreflightInfo = CFSTR("FirmwarePreflightInfo");
    static const CFStringRef kMGIntegratedCircuitCardIdentifier = CFSTR("IntegratedCircuitCardIdentifier");
    static const CFStringRef kMGAirplaneMode = CFSTR("AirplaneMode");
    static const CFStringRef kMGAllowYouTube = CFSTR("AllowYouTube");
    static const CFStringRef kMGAllowYouTubePlugin = CFSTR("AllowYouTubePlugin");
    static const CFStringRef kMGMinimumSupportediTunesVersion = CFSTR("MinimumSupportediTunesVersion");
    static const CFStringRef kMGProximitySensorCalibration = CFSTR("ProximitySensorCalibration");
    static const CFStringRef kMGRegionCode = CFSTR("RegionCode");
    static const CFStringRef kMGRegionInfo = CFSTR("RegionInfo");
    static const CFStringRef kMGRegulatoryIdentifiers = CFSTR("RegulatoryIdentifiers");
    static const CFStringRef kMGSBAllowSensitiveUI = CFSTR("SBAllowSensitiveUI");
    static const CFStringRef kMGSBCanForceDebuggingInfo = CFSTR("SBCanForceDebuggingInfo");
    static const CFStringRef kMGSDIOManufacturerTuple = CFSTR("SDIOManufacturerTuple");
    static const CFStringRef kMGSDIOProductInfo = CFSTR("SDIOProductInfo");
    static const CFStringRef kMGShouldHactivate = CFSTR("ShouldHactivate");
    static const CFStringRef kMGSigningFuse = CFSTR("SigningFuse");
    static const CFStringRef kMGSoftwareBehavior = CFSTR("SoftwareBehavior");
    static const CFStringRef kMGSoftwareBundleVersion = CFSTR("SoftwareBundleVersion");
    static const CFStringRef kMGSupportedDeviceFamilies = CFSTR("SupportedDeviceFamilies");
    static const CFStringRef kMSupportedKeyboards = CFSTR("SupportedKeyboards");
    static const CFStringRef kMGTotalSystemAvailable = CFSTR("TotalSystemAvailable");

#pragma mark - Capability Information

    static const CFStringRef kMGAllDeviceCapabilities = CFSTR("AllDeviceCapabilities");
    static const CFStringRef kMGAppleInternalInstallCapability = CFSTR("AppleInternalInstallCapability");
    static const CFStringRef kMGExternalChargeCapability = CFSTR("ExternalChargeCapability");
    static const CFStringRef kMGForwardCameraCapability = CFSTR("ForwardCameraCapability");
    static const CFStringRef kMGPanoramaCameraCapability = CFSTR("PanoramaCameraCapability");
    static const CFStringRef kMGRearCameraCapability = CFSTR("RearCameraCapability");
    static const CFStringRef kMGHasAllFeaturesCapability = CFSTR("HasAllFeaturesCapability");
    static const CFStringRef kMGHasBaseband = CFSTR("HasBaseband");
    static const CFStringRef kMGHasInternalSettingsBundle = CFSTR("HasInternalSettingsBundle");
    static const CFStringRef kMGHasSpringBoard = CFSTR("HasSpringBoard");
    static const CFStringRef kMGInternalBuild = CFSTR("InternalBuild");
    static const CFStringRef kMGIsSimulator = CFSTR("IsSimulator");
    static const CFStringRef kMGIsThereEnoughBatteryLevelForSoftwareUpdate = CFSTR("IsThereEnoughBatteryLevelForSoftwareUpdate");
    static const CFStringRef kMGIsUIBuild = CFSTR("IsUIBuild");

#pragma mark - Regional Behaviour

    static const CFStringRef kMGRegionalBehaviorAll = CFSTR("RegionalBehaviorAll");
    static const CFStringRef kMGRegionalBehaviorChinaBrick = CFSTR("RegionalBehaviorChinaBrick");
    static const CFStringRef kMGRegionalBehaviorEUVolumeLimit = CFSTR("RegionalBehaviorEUVolumeLimit");
    static const CFStringRef kMGRegionalBehaviorGB18030 = CFSTR("RegionalBehaviorGB18030");
    static const CFStringRef kMGRegionalBehaviorGoogleMail = CFSTR("RegionalBehaviorGoogleMail");
    static const CFStringRef kMGRegionalBehaviorNTSC = CFSTR("RegionalBehaviorNTSC");
    static const CFStringRef kMGRegionalBehaviorNoPasscodeLocationTiles = CFSTR("RegionalBehaviorNoPasscodeLocationTiles");
    static const CFStringRef kMGRegionalBehaviorNoVOIP = CFSTR("RegionalBehaviorNoVOIP");
    static const CFStringRef kMGRegionalBehaviorNoWiFi = CFSTR("RegionalBehaviorNoWiFi");
    static const CFStringRef kMGRegionalBehaviorShutterClick = CFSTR("RegionalBehaviorShutterClick");
    static const CFStringRef kMGRegionalBehaviorVolumeLimit = CFSTR("RegionalBehaviorVolumeLimit");

#pragma mark - Wireless Information

    static const CFStringRef kMGActiveWirelessTechnology = CFSTR("ActiveWirelessTechnology");
    static const CFStringRef kMGWifiAddress = CFSTR("WifiAddress");
    static const CFStringRef kMGWifiAddressData = CFSTR("WifiAddressData");
    static const CFStringRef kMGWifiVendor = CFSTR("WifiVendor");

#pragma mark - FaceTime Information

    static const CFStringRef kMGFaceTimeBitRate2G = CFSTR("FaceTimeBitRate2G");
    static const CFStringRef kMGFaceTimeBitRate3G = CFSTR("FaceTimeBitRate3G");
    static const CFStringRef kMGFaceTimeBitRateLTE = CFSTR("FaceTimeBitRateLTE");
    static const CFStringRef kMGFaceTimeBitRateWiFi = CFSTR("FaceTimeBitRateWiFi");
    static const CFStringRef kMGFaceTimeDecodings = CFSTR("FaceTimeDecodings");
    static const CFStringRef kMGFaceTimeEncodings = CFSTR("FaceTimeEncodings");
    static const CFStringRef kMGFaceTimePreferredDecoding = CFSTR("FaceTimePreferredDecoding");
    static const CFStringRef kMGFaceTimePreferredEncoding = CFSTR("FaceTimePreferredEncoding");

#pragma mark - More Device Capabilities

    static const CFStringRef kMGDeviceSupportsFaceTime = CFSTR("DeviceSupportsFaceTime");
    static const CFStringRef kMGDeviceSupportsTethering = CFSTR("DeviceSupportsTethering");
    static const CFStringRef kMGDeviceSupportsSimplisticRoadMesh = CFSTR("DeviceSupportsSimplisticRoadMesh");
    static const CFStringRef kMGDeviceSupportsNavigation = CFSTR("DeviceSupportsNavigation");
    static const CFStringRef kMGDeviceSupportsLineIn = CFSTR("DeviceSupportsLineIn");
    static const CFStringRef kMGDeviceSupports9Pin = CFSTR("DeviceSupports9Pin");
    static const CFStringRef kMGDeviceSupports720p = CFSTR("DeviceSupports720p");
    static const CFStringRef kMGDeviceSupports4G = CFSTR("DeviceSupports4G");
    static const CFStringRef kMGDeviceSupports3DMaps = CFSTR("DeviceSupports3DMaps");
    static const CFStringRef kMGDeviceSupports3DImagery = CFSTR("DeviceSupports3DImagery");
    static const CFStringRef kMGDeviceSupports1080p = CFSTR("DeviceSupports1080p");

#if __cplusplus
}
#endif

#endif /* LIBMOBILEGESTALT_H_ */
