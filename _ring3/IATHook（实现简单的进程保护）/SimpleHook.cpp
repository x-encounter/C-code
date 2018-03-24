// SimpleHook.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
DWORD* lpAddr;
PROC OldProc;
BOOL  __stdcall  MyTerminateProcess(HANDLE hProcess,UINT uExitCode)
{
	MessageBox(NULL,"没法结束进程了吧","API HOOK",0);
	return 0;
}

int  ApiHook(char *DllName,//DLL文件名
			  PROC OldFunAddr,//要HOOK的函数地址
			  PROC NewFunAddr//我们够造的函数地址
			  )
{

	// LPVOID lpBase=MapViewOfFile(hMap,FILE_MAP_READ,0,0,0); 返回内存文件映射句柄
	HMODULE lpBase = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER *dosHeader;
	IMAGE_NT_HEADERS *ntHeader;
	IMAGE_IMPORT_BY_NAME *ImportName;
	//定位到DOS头
	dosHeader=(IMAGE_DOS_HEADER*)lpBase;
	//定位到PE头
	ntHeader=(IMAGE_NT_HEADERS32*)((BYTE*)lpBase+dosHeader->e_lfanew);
	//定位到导入表
	IMAGE_IMPORT_DESCRIPTOR *pImportDesc=(IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)lpBase+ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	//循环遍历IMAGE_IMPORT_DESCRIPTOR机构数组
	while(pImportDesc->FirstThunk)
	{
		//得到DLL文件名
		char* pszDllName = (char*)((BYTE*)lpBase + pImportDesc->Name);
		//比较得到的DLL文件名是否和要HOOK函数所在的DLL相同
		if(lstrcmpiA(pszDllName, DllName) == 0)
		{
			break;
		}
		pImportDesc++;
	}
	//定位到FirstThunk参数指向的IMAGE_THUNK_DATA，此时这个结构已经是函数入口点地址了
	IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)
		((BYTE*)lpBase + pImportDesc->FirstThunk);
	//遍历这部分IAT表
	while(pThunk->u1.Function)
	{
		lpAddr = (DWORD*)&(pThunk->u1.Function);//获得我们要HOOK 的api函数的入口点地址在IAT表中的内存地址
		//比较函数地址是否相同
		if(*lpAddr == (DWORD)OldFunAddr)
		{	
			DWORD dwOldProtect;
			//修改内存包含属性
			VirtualProtect(lpAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
			//API函数的入口点地址改成我们构造的函数的地址
			WriteProcessMemory(GetCurrentProcess(),lpAddr, &NewFunAddr, sizeof(DWORD), NULL);
		}
		pThunk++;
	}
	return 0;
}

BOOL APIENTRY DllMain( HANDLE hModule, 
					  DWORD  ul_reason_for_call, 
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//得到TerminateProcess函数地址
		OldProc = (PROC)TerminateProcess;
		//定位，修改IAT表
		ApiHook("kernel32.dll",OldProc,(PROC)MyTerminateProcess);
		break;
	case DLL_PROCESS_DETACH:
		//恢复IAT表中API函数的入口点地址
		WriteProcessMemory(GetCurrentProcess(),lpAddr, &OldProc, sizeof(DWORD), NULL);
		break;	
	}
    return TRUE;	
}

