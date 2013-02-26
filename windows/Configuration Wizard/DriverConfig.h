// DriverConfig.h: interface for the CDriverConfig class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DRIVERCONFIG_H__6181CB37_CC70_46BD_B276_48306763394F__INCLUDED_)
#define AFX_DRIVERCONFIG_H__6181CB37_CC70_46BD_B276_48306763394F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Singleton.h"
#include <string>

#define DEST_MAC_SIZE 6
#define CONFIG_PROC_SIZE 13
#define DRIVER_NAME_SIZE 12
#define DEVICE_SIZE 40

class CDriverConfig 
{
public:
	virtual ~CDriverConfig();
	bool LoadConfig();
	bool SaveConfig();
	const std::string GetFileLocation();
	void SetFileLocation(const char *strFileLocation);
	const std::string GetErrorString();

	const std::string GetDestinationMAC();
	void SetDestinationMAC(std::string &strMAC);
	void SetDestinationMAC(const char *strMAC);

	const std::string GetDestinationIP();
	void SetDestinationIP(std::string &strIP);
	void SetDestinationIP(const char *strIP);

	const unsigned short GetDestinationPort();
	const std::string GetDestinationPortAsString();
	void SetDestinationPort(const unsigned short usDestPort);

	const unsigned int GetMagicValue();
	const std::string GetMagicValueAsString();
	void SetMagicValue(const unsigned int uiMagicValue);

	const std::string GetDeviceName();
	void SetDeviceName(std::string &strDeviceName);
	void SetDeviceName(const char *strDeviceName);

	const std::string GetConfigFileName();
	void SetConfigFileName(std::string &strMAC);
	void SetConfigFileName(const char *strMAC);
private:
	std::string m_strErrorString;
	std::string m_strFileLocation;
	std::string m_strDestinationMAC;
	std::string m_strDestinationIP;
	std::string m_strDeviceName;
	std::string m_strConfigFileName;
	unsigned short m_usDestinationPort;
	unsigned int m_uiMagicValue;
	
	PIMAGE_SECTION_HEADER GetSectionHeader(PSTR name, PIMAGE_NT_HEADERS pNTHeader);
	DWORD FindExport(DWORD base, PIMAGE_NT_HEADERS pNTHeader, const char *strExportName);
	DWORD GetExportValue(PIMAGE_DOS_HEADER dosHeader, const char *strExportName);
	
	void SetErrorString(std::string strErrorString);
	void ClearErrorString();

	bool GetDestinationMACFromDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool GetDestinationIPFromDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool GetDestinationPortFromDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool GetMagicValueFromDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool GetDeviceNameFromDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool GetConfigFileNameFromDriver(const PIMAGE_DOS_HEADER pDosHeader);

	bool StoreDestinationMACInDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool StoreDestinationIPInDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool StoreDestinationPortInDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool StoreMagicValueInDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool StoreDeviceNameInDriver(const PIMAGE_DOS_HEADER pDosHeader);
	bool StoreConfigFileNameInDriver(const PIMAGE_DOS_HEADER pDosHeader);

	bool GetLongFromDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, unsigned long *pulValue);
	bool StoreLongInDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, const unsigned long pulValue);
	bool GetStringFromDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, const unsigned int uiValueLen, char *strValue);
	bool StoreStringInDriver(const PIMAGE_DOS_HEADER pDosHeader, const char *strExportName, const char *strValue, const unsigned int uiMaxLen);

	const std::string GetAutoDetectTargetIP();
	const static std::string strAutoDetectionTargetIPs[];

	std::string AutoDetectDeviceName();
	std::string FindRegistryAdapter(const char *strIP);
	friend class CSingleton<CDriverConfig>;
  CDriverConfig();
  CDriverConfig(const CDriverConfig&);
  CDriverConfig& operator=(const CDriverConfig&);
};

#endif // !defined(AFX_DRIVERCONFIG_H__6181CB37_CC70_46BD_B276_48306763394F__INCLUDED_)
