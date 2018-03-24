#include "stdafx.h"
#include "ILHook.h"





CILHook::CILHook(){
	m_pfnOrig = NULL;
	ZeroMemory(m_bOldBytes,7);
	ZeroMemory(bJmpCode, 7);
}

CILHook::~CILHook(){
	UnHook();
	m_pfnOrig = NULL;
	ZeroMemory(m_bOldBytes,7);
	ZeroMemory(bJmpCode, 7);
}

BOOL CILHook::Hook(LPCWSTR pszModuleName, LPSTR pszFuncName, PROC pfnHookFunc)
{
	BOOL bRet = FALSE;
	//获取指定模块中的函数地址
	m_pfnOrig = (PROC)GetProcAddress(GetModuleHandle(pszModuleName),pszFuncName);
	if (m_pfnOrig != NULL)
	{
		//保存该地址处5字节的内容
		DWORD dwNum = 0;
		ReadProcessMemory(GetCurrentProcess(),m_pfnOrig,m_bOldBytes,7,0);
		//构造jmp指令
		//bJmpCode[7] = {'\xb8','\0','\0','\0','\0','\xFF','\xE0'};
		byte byteData[4]; // byte数组，示例
		DWORD dwData = (DWORD)pfnHookFunc; // 函数地址
		//通过位运算依次取出目的地址的两位
		byteData[0] = (dwData & 0xFF000000) >> 24; 
		byteData[1] = (dwData & 0x00FF0000) >> 16; 
		byteData[2] = (dwData & 0x0000FF00) >> 8; 
		byteData[3] = (dwData & 0x000000FF); 
		bJmpCode[0] = '\xb8';
		bJmpCode[1] = byteData[3];
		bJmpCode[2] = byteData[2];
		bJmpCode[3] = byteData[1];
		bJmpCode[4] = byteData[0];
		bJmpCode[5] = '\xFF';
		bJmpCode[6] = '\xE0';
		
		WriteProcessMemory(GetCurrentProcess(), m_pfnOrig, bJmpCode, 7, 0);
		bRet = TRUE;
	}
	return bRet;
}VOID CILHook::UnHook()
{
	if (m_pfnOrig != 0)
	{
		DWORD dwNum = 0;
		WriteProcessMemory(GetCurrentProcess(), m_pfnOrig, m_bOldBytes, 7, 0);
	}
}

/*
函数名称：ReHook
函数功能：重新对函数进行挂钩
*/
BOOL CILHook::ReHook()
{
	BOOL bRet = FALSE;

	if (m_pfnOrig != 0)
	{
		DWORD dwNum = 0;
		WriteProcessMemory(GetCurrentProcess(), m_pfnOrig, bJmpCode, 7, 0);

		bRet = TRUE;
	}

	return bRet;
}