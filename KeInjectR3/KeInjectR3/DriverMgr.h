#pragma once
#include "windows.h"
#include <tchar.h>
#include <winioctl.h>


#define SYSNAME _T("KeInject.sys")
#define SERVICE_NAME  _T("HadesService")
#define DISPLAY_NAME _T("HadesService")


TCHAR g_szSysFile[MAX_PATH] = { 0 };

SC_HANDLE g_hSCManager = NULL;

SC_HANDLE g_hServiceDDK = NULL;

DWORD g_dwLastError;

HANDLE g_hDevice = INVALID_HANDLE_VALUE;


void GetSysFullPath(PTCHAR szSysFileName);
bool Install();
bool Start();
bool Stop();
bool Remove();
bool OpenDevice(PTCHAR pLinkName);
BOOL IoCtrlDriver(DWORD dwIoCode, PVOID pInBuff, DWORD InBuffLen, PVOID pOutBuff, DWORD OutBuffLen, DWORD *RealRetBytes);

bool CloseDevice()
{
	if (g_hDevice == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	CloseHandle(g_hDevice);
	return true;
}

DWORD CTL_CODE_GEN(DWORD lngFunction)
{
	return (FILE_DEVICE_UNKNOWN * 65536) | (FILE_ANY_ACCESS * 16384) | (lngFunction * 4) | METHOD_BUFFERED;
}

BOOL IoCtrlDriver(DWORD dwIoCode, PVOID pInBuff, DWORD InBuffLen, PVOID pOutBuff, DWORD OutBuffLen, DWORD *RealRetBytes)
{
	DWORD dwRetByte;
	BOOL bRet = DeviceIoControl(g_hDevice, CTL_CODE_GEN(dwIoCode), pInBuff, InBuffLen, pOutBuff, OutBuffLen, &dwRetByte, NULL);
	if (RealRetBytes)
		*RealRetBytes = dwRetByte;
	return bRet;
}

bool OpenDevice(PTCHAR pLinkName)//example: \\\\.\\xxoo
{
	if (g_hDevice != INVALID_HANDLE_VALUE)
		return TRUE;
	g_hDevice = CreateFile(pLinkName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (g_hDevice != INVALID_HANDLE_VALUE)
		return TRUE;
	else
		return FALSE;
}

void GetSysFullPath(PTCHAR szSysFileName)
{
	GetModuleFileName(0, g_szSysFile, MAX_PATH);
	for (size_t i = _tcslen(g_szSysFile) - 1;i > 0; i--)
	{
		if (g_szSysFile[i] == '\\')
		{
			g_szSysFile[i + 1] = '\0';
			break;
		}
	}
	_tcscat_s(g_szSysFile, szSysFileName);
	return;
}

bool Remove()
{
	g_hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == g_hSCManager)
	{
		g_dwLastError = GetLastError();
	}
	g_hServiceDDK = OpenService(g_hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (NULL == g_hServiceDDK)
	{
		CloseServiceHandle(g_hSCManager);
	}

	if (!DeleteService(g_hServiceDDK))
	{
		g_dwLastError = GetLastError();
		return false;
	}
	return true;
}

bool Stop()
{
	g_hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == g_hSCManager)
	{
		g_dwLastError = GetLastError();
	}
	g_hServiceDDK = OpenService(g_hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (NULL == g_hServiceDDK)
	{
		CloseServiceHandle(g_hSCManager);
	}

	SERVICE_STATUS ss;
	if (!ControlService(g_hServiceDDK, SERVICE_CONTROL_STOP, &ss))
	{
		g_dwLastError = GetLastError();
		return false;
	}

	return true;
}

bool Start()
{
	if (!StartService(g_hServiceDDK, NULL, NULL))
	{
		g_dwLastError = GetLastError();
		return false;
	}
	return true;
}

bool Install()
{
	g_hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == g_hSCManager)
	{
		g_dwLastError = GetLastError();
		return false;
	}
	g_hServiceDDK = CreateService(
		g_hSCManager,
		SERVICE_NAME,
		DISPLAY_NAME,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		g_szSysFile,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);//
	if (NULL == g_hServiceDDK)
	{
		g_dwLastError = GetLastError();
		if (ERROR_SERVICE_EXISTS == g_dwLastError)
		{
			g_hServiceDDK = OpenService(g_hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
			if (NULL == g_hServiceDDK)
			{
				CloseServiceHandle(g_hSCManager);
				return false;
			}
		}
		else
		{
			CloseServiceHandle(g_hSCManager);
			return false;
		}
	}
	return true;
}