package shutdown

import (
	"syscall"
	"unsafe"
)

func MustLoadLibrary(name string) uintptr {
	lib, err := syscall.LoadLibrary(name)
	if err != nil {
		panic(err)
	}

	return uintptr(lib)
}

func MustGetProcAddress(lib uintptr, name string) uintptr {
	addr, err := syscall.GetProcAddress(syscall.Handle(lib), name)
	if err != nil {
		panic(err)
	}

	return uintptr(addr)
}

var (
	// Library
	libuser32 					uintptr
	libadvapi32 				uintptr
	libkernel32 				uintptr

	exitWindowsEx               uintptr
	setWindowRgn                uintptr
	registerDeviceNotificationW uintptr
	openProcessToken      uintptr
	lookupPrivilegeValueA uintptr
	adjustTokenPrivileges uintptr
	getCurrentProcess uintptr
)

func init() {
	libadvapi32 = MustLoadLibrary("advapi32.dll")
	libuser32 = MustLoadLibrary("user32.dll")
	libkernel32 = MustLoadLibrary("kernel32.dll")

	openProcessToken = MustGetProcAddress(libadvapi32, "OpenProcessToken")
	lookupPrivilegeValueA = MustGetProcAddress(libadvapi32, "LookupPrivilegeValueA")
	adjustTokenPrivileges = MustGetProcAddress(libadvapi32, "AdjustTokenPrivileges")
	exitWindowsEx = MustGetProcAddress(libuser32, "ExitWindowsEx")
	getCurrentProcess = MustGetProcAddress(libkernel32, "GetCurrentProcess")
}

const (
	EWX_LOGOFF          = 0
	EWX_SHUTDOWN        = 0x00000001
	EWX_REBOOT          = 0x00000002
)

// winnt.h OpenProcessToken DesiredAccess
const (
	TOKEN_QUERY             = 0x0008
	TOKEN_ADJUST_PRIVILEGES = 0x0020
)

const (
	SE_PRIVILEGE_ENABLED            = uint32(0x00000002)
)

const (
	SE_SHUTDOWN_NAME               = "SeShutdownPrivilege"
)

const (
	ANYSIZE_ARRAY = 1
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}


type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [ANYSIZE_ARRAY]LUID_AND_ATTRIBUTES
}

type (
	BOOL    int32
)

type (
	HANDLE    uintptr
)

func boolToBOOL(value bool) BOOL {
	if value {
		return 1
	}

	return 0
}

func StringToBytePtr(str string) *byte {
	return syscall.StringBytePtr(str)
}

func ExitWindowsEx(uFlags, dwReason uint32) bool {
	ret, _, _ := syscall.Syscall(exitWindowsEx, 2,
		uintptr(uFlags),
		uintptr(dwReason),
		0)

	return ret != 0
}

func OpenProcessToken(ProcessHandle HANDLE, DesiredAccess uint32, TokenHandle *HANDLE) bool {
	ret, _, _ := syscall.Syscall(openProcessToken, 3,
		uintptr(ProcessHandle),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(TokenHandle)))

	return ret != 0
}

func LookupPrivilegeValueA(lpSystemName, lpName *byte, lpLuid *LUID) bool {
	ret, _, _ := syscall.Syscall(lookupPrivilegeValueA, 3,
		uintptr(unsafe.Pointer(lpSystemName)),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpLuid)))

	return ret != 0
}

func getPrivileges() {
	var hToken HANDLE
	var tkp TOKEN_PRIVILEGES

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)
	LookupPrivilegeValueA(nil, StringToBytePtr(SE_SHUTDOWN_NAME), &tkp.Privileges[0].Luid)
	tkp.PrivilegeCount = 1
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	AdjustTokenPrivileges(hToken, false, &tkp, 0, nil, nil)
}

func AdjustTokenPrivileges(TokenHandle HANDLE, DisableAllPrivileges bool, NewState *TOKEN_PRIVILEGES, BufferLength uint32, PreviousState *TOKEN_PRIVILEGES, ReturnLength *uint16) bool {
	ret, _, _ := syscall.Syscall6(adjustTokenPrivileges, 6,
		uintptr(TokenHandle),
		uintptr(boolToBOOL(DisableAllPrivileges)),
		uintptr(unsafe.Pointer(NewState)),
		uintptr(BufferLength),
		uintptr(unsafe.Pointer(PreviousState)),
		uintptr(unsafe.Pointer(ReturnLength)))

	return ret != 0
}

func GetCurrentProcess() HANDLE {
	ret, _, _ := syscall.Syscall(getCurrentProcess, 0,
		0,
		0,
		0)

	return HANDLE(ret)
}

func LogOff() {
	ExitWindowsEx(EWX_LOGOFF, 0)
}

func Reboot() {
	getPrivileges()
	ExitWindowsEx(EWX_REBOOT, 0)
}

func Shutdown() {
	getPrivileges()
	ExitWindowsEx(EWX_SHUTDOWN, 0)
}