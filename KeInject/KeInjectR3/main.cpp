#include "windows.h"
#include "DriverMgr.h"
#include <stdlib.h>
#include <stdio.h>



#define DEVICE_LINKNAME L"\\\\.\\HadesLinkName" //WCHAR
#define IOCTL_INJECT_MODULE 0x801


#define MODULE_MAX_LENGTH 512
typedef struct _INJECTION_INFO
{
	ULONG64	Pid;
	TCHAR	ModulePath[MODULE_MAX_LENGTH];
} INJECTION_INFO, *PINJECTION_INFO;

INJECTION_INFO stInjectInfo = { 0 };


bool load();
bool unload();


void GetUserCtrlCommand()
{
	printf("1.OpenDevice\n");

	printf("2.IoCtrlDriver--APCInject\n");

	printf("3.CloseDevice and unload\n");

	printf("4.exit input\n");


	int nCommand = 0;

	while (true)
	{
		printf("input:");
		scanf_s("%d", &nCommand);
		switch (nCommand)
		{
		case 1:
		{
			if (OpenDevice(DEVICE_LINKNAME))
				printf("Open Device Handle:%d\n", g_hDevice);
			else
				printf("OpenDevice err:%d\n", g_hDevice);
			break;
		}
		case 2:
		{
			int Pid = 0;
			TCHAR ModulePath[MODULE_MAX_LENGTH] = { 0 };
			printf("Pid:");
			scanf_s("%d", &Pid);
			printf("ModulePath:");
			_tscanf_s(_T("%s"),ModulePath);
			stInjectInfo.Pid = Pid;
			memcpy(stInjectInfo.ModulePath, ModulePath, _tcslen(ModulePath)*sizeof(TCHAR));
			PVOID pOutBuffer=NULL;
			DWORD dwOutBufferSize=0;
			DWORD dwRealRetByte=0;
			IoCtrlDriver(IOCTL_INJECT_MODULE,&stInjectInfo,sizeof(INJECTION_INFO),pOutBuffer, dwOutBufferSize,&dwRealRetByte);
			break;
		}
		case 3:
		{
			if (CloseDevice())
			{
				printf("Close Device Handle:%d\n", g_hDevice);
			}
			if (unload())
			{
				printf("unload success\n");
			}
			break;
		}
		default:return;
			break;
		}
	}

	return;
}


bool unload()
{
	if (!Stop())
	{
		printf("Stop->LastError:%d\n", g_dwLastError);
	}
	
	if (!Remove())
	{
		printf("Remove->LastError:%d\n", g_dwLastError);
		return false;
	}
	return true;
}

bool load()
{
	if (!Install())
	{
		printf("Install->LastError:%d\n", g_dwLastError);
		return false;
	}

	if (!Start())
	{
		printf("Start->LastError:%d\n", g_dwLastError);
		return false;
	}

	return true;
}


int main()
{
	int Pid = 7008;
	TCHAR ModulePath[MODULE_MAX_LENGTH] =  L" C:\\Users\\lhl.liu\\Desktop\\Api_Monitor_DLL.dll";
	/*printf("Pid:");
	scanf_s("%d", &Pid);
	printf("Pid: %d\n", Pid);
	printf("ModulePath:");*/
	/*_tscanf_s(_T("%s"), ModulePath);
	_tprintf(_T("ModulePath:%ws\n"), ModulePath);*/
	stInjectInfo.Pid = Pid;
	memcpy(stInjectInfo.ModulePath, ModulePath, _tcslen(ModulePath) * sizeof(TCHAR));
	PVOID pOutBuffer = NULL;
	DWORD dwOutBufferSize = 0;
	DWORD dwRealRetByte = 0;
	IoCtrlDriver(IOCTL_INJECT_MODULE, &stInjectInfo, sizeof(INJECTION_INFO), pOutBuffer, dwOutBufferSize, &dwRealRetByte);
	//GetUserCtrlCommand();
	/*printf("Hades\n");

	GetSysFullPath(_T("KeInject.sys"));

	if (!load())
	{
		unload();
	}
	else
	{
		printf("load success\n");

		GetUserCtrlCommand();
	}*/

	system("pause");

	return 0;
}

