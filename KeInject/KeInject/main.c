#pragma once
#include "ntddk.h"
#include "Inject.h"
#include <tchar.h>


#define DEVICE_NAME  L"\\Device\\HadesDevName"
#define DEVICE_LINKNAME L"\\??\\HadesLinkName"

#define IOCTL_INJECT_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MODULE_MAX_LENGTH 512

typedef struct _INJECTION_INFO
{
	ULONG64	Pid;
	WCHAR	ModulePath[MODULE_MAX_LENGTH];
} INJECTION_INFO, *PINJECTION_INFO;


NTSTATUS DeviceControlDispatch(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
)
{
	// retn status							 ;
	NTSTATUS status;
	// Get IRP Stack					 ;
	PIO_STACK_LOCATION pIrpStack;
	// Get IoControlCode				 ;
	ULONG ulIoControlCode;
	// Get SystemBuffer					 ;
	PVOID pIoBuffer;
	// Get Input Size					 ;
	ULONG ulInputSize;
	// Get Output Size					 ;
	ULONG ulOutputSize;

	PINJECTION_INFO pInjectInfo;
	UNICODE_STRING usModulePath = { 0 };

	UNREFERENCED_PARAMETER(pDeviceObject);

#if DBG
	//KdBreakPoint();
#else

#endif

	// retn status
	status = STATUS_INVALID_DEVICE_REQUEST;
	// Get IRP Stack
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	// Get IoControlCode
	ulIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	// Get SystemBuffer
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// Get Input Size
	ulInputSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	// Get Output Size
	ulOutputSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	// Dispatch
	switch (ulIoControlCode)
	{
	case IOCTL_INJECT_MODULE:
	{
		if (pIoBuffer != NULL)
		{
			DEBUG_LOG(IOCTL_INJECT_MODULE, "IOCTL_INJECT_MODULE");

			pInjectInfo = (PINJECTION_INFO)pIoBuffer;

			pInjectInfo->ModulePath[MODULE_MAX_LENGTH - 1] = 0;

			RtlInitUnicodeString(&usModulePath, pInjectInfo->ModulePath);

			DEBUG_LOG(pInjectInfo->Pid, "pInjectInfo->Pid");
			DEBUG_LOG(pInjectInfo->ModulePath, "pInjectInfo->ModulePath");

			status = InjectModuleByAPC((HANDLE)pInjectInfo->Pid, &usModulePath);
		}

		break;
	}
	default:
		break;
	}

	// retn complete bytes
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = ulOutputSize;
	else
		pIrp->IoStatus.Information = 0;
	// retn status
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
}



NTSTATUS DeviceDefaultDispatch(DEVICE_OBJECT *pDeviceObject, IRP *pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	// Set IRP status
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	// Set IRP Operation Byte
	pIrp->IoStatus.Information = 0;
	// Request IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING usDeviceSymlink;
	DEBUG_LOG(STATUS_SUCCESS, "DriverUnload");
	// Delete Device Link Name and Device Name
	RtlInitUnicodeString(&usDeviceSymlink, L"\\??\\HadesLinkName");
	IoDeleteSymbolicLink(&usDeviceSymlink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
#if DBG
	//KdBreakPoint();
#else

#endif
	size_t i = 0;
	// Create SymbolLink Name
	UNICODE_STRING usDeviceSymlink;
	// Create Device
	UNICODE_STRING usDeviceName;
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS status;
	UNREFERENCED_PARAMETER(pRegistryPath);

	DEBUG_LOG(STATUS_SUCCESS, "DriverEntry");

	// Register Unload Function
	pDriverObject->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&usDeviceName, L"\\Device\\HadesDevName");

	status = IoCreateDevice(
		pDriverObject,				// Driver Object
		0,							// Extend device size
		&usDeviceName,				// Device Name
		FILE_DEVICE_UNKNOWN,		// Device Type
		FILE_DEVICE_SECURE_OPEN,	// Device Characteristics
		FALSE,						// Is it exclusive
		&pDeviceObject				// Device Object -- OUT
	);
	if (!NT_SUCCESS(status))
	{
		DEBUG_LOG(status, "CreateDevice Fail");
		return STATUS_UNSUCCESSFUL;
	}


	RtlInitUnicodeString(&usDeviceSymlink, L"\\??\\HadesLinkName");
	status = IoCreateSymbolicLink(&usDeviceSymlink, &usDeviceName);
	if (!NT_SUCCESS(status))
	{
		DEBUG_LOG(status, "CreateSymbolicLink Fail");
		return STATUS_UNSUCCESSFUL;
	}

	// Fill IRP Function
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DeviceDefaultDispatch;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;

	return STATUS_SUCCESS;
}