#include "stdafx.h"
#include "ILHook.h"





CILHook::CILHook(){
	m_pfnOrig = NULL;
	ZeroMemory(m_bOldBytes,5);
	ZeroMemory(m_bNewBytes,5);
}

CILHook::~CILHook(){
	UnHook();
	m_pfnOrig = NULL;
	ZeroMemory(m_bOldBytes,5);
	ZeroMemory(m_bNewBytes,5);
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
		ReadProcessMemory(GetCurrentProcess(),m_pfnOrig,m_bOldBytes,5,0);
		//构造jmp指令
		m_bNewBytes[0] = '\xe9';
		//jmp后面的地位计算公式为：目标地址-原地址-5
		*(DWORD *)(m_bNewBytes + 1) = (DWORD)pfnHookFunc - (DWORD)m_pfnOrig - 5;

		WriteProcessMemory(GetCurrentProcess(),m_pfnOrig,m_bNewBytes,5,0);
		bRet = TRUE;
	}
	return bRet;
}VOID CILHook::UnHook()
{
	if (m_pfnOrig != 0)
	{
		DWORD dwNum = 0;
		WriteProcessMemory(GetCurrentProcess(), m_pfnOrig, m_bOldBytes, 5, 0);
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
		WriteProcessMemory(GetCurrentProcess(), m_pfnOrig, m_bNewBytes, 5, 0);

		bRet = TRUE;
	}

	return bRet;
}