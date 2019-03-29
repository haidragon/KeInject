#pragma once
#include "ntddk.h"

#define  DEBUG_LOG(var,message) {KdPrint(("[Hades's KeInject] -> [%p] -> %s \n",var,message));}

NTSTATUS InjectModuleByAPC( HANDLE ProcessId, PUNICODE_STRING ModulePath);