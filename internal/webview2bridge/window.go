// Package webview2bridge embeds một (hoặc nhiều) WebView2 instance phụ
// trong process Wails để chạy hCaptcha + TTS như khi user paste JS vào
// DevTools console của Chrome thật. Tránh hoàn toàn Cloudflare TLS
// fingerprint detection mà subprocess Playwright/Camoufox bị flag.
//
// Mỗi worker = 1 OS thread (LockOSThread) + 1 message-only Win32 window
// + 1 Chromium controller + 1 LocalProxy. Khi gặp 401 detected_unusual_activity
// → teardown WV2, đợi proxy auto-rotate (~60s server-side) rồi respawn WV2
// với IP mới.
package webview2bridge

import (
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	ole32    = windows.NewLazySystemDLL("ole32.dll")

	procCoInitializeEx = ole32.NewProc("CoInitializeEx")
	procCoUninitialize = ole32.NewProc("CoUninitialize")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procPeekMessageW     = user32.NewProc("PeekMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procShowWindow       = user32.NewProc("ShowWindow")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

const (
	wsPopup        = 0x80000000
	wsExToolwindow = 0x00000080
	wsExNoactivate = 0x08000000
	wmDestroy      = 0x0002
	swHide         = 0
	swShow         = 5

	pmRemove = 0x0001

	coinitApartmentThreaded = 0x2
)

// coInitializeApartment khởi tạo COM cho thread hiện tại (STA). Bắt buộc
// trước khi dùng WebView2 trên thread mới (worker pool). pkg/edge có gọi
// trong init() nhưng chỉ trên 1 goroutine import-time, không tự lan sang
// goroutine worker.
//
// Trả error chỉ khi HRESULT < 0 và khác RPC_E_CHANGED_MODE / S_FALSE
// (đã init, chấp nhận).
func coInitializeApartment() error {
	r, _, _ := procCoInitializeEx.Call(0, uintptr(coinitApartmentThreaded))
	hr := int32(r)
	// S_OK=0, S_FALSE=1 (đã init), RPC_E_CHANGED_MODE=0x80010106 (đã init khác mode → ignore).
	if hr >= 0 || uint32(r) == 0x80010106 {
		return nil
	}
	return fmt.Errorf("CoInitializeEx HRESULT=0x%08x", uint32(r))
}

func coUninitialize() {
	_, _, _ = procCoUninitialize.Call()
}

type wndclassexw struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type winMsg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

const windowClassName = "ElevenFlowWV2Bridge"

var (
	classOnce sync.Once
	classErr  error
)

func defaultWndProc(hwnd windows.Handle, message uint32, wparam, lparam uintptr) uintptr {
	if message == wmDestroy {
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(message), wparam, lparam)
	return r
}

func ensureWindowClass() error {
	classOnce.Do(func() {
		hInstance, _, _ := procGetModuleHandleW.Call(0)
		classNamePtr, err := windows.UTF16PtrFromString(windowClassName)
		if err != nil {
			classErr = fmt.Errorf("class name UTF16: %w", err)
			return
		}
		wc := wndclassexw{
			cbSize:        uint32(unsafe.Sizeof(wndclassexw{})),
			lpfnWndProc:   syscall.NewCallback(defaultWndProc),
			hInstance:     windows.Handle(hInstance),
			lpszClassName: classNamePtr,
		}
		atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 {
			if errno, ok := regErr.(syscall.Errno); ok && errno == 1410 {
				return // class already registered (race / re-init), OK
			}
			classErr = fmt.Errorf("RegisterClassExW: %v", regErr)
		}
	})
	return classErr
}

// createHiddenWindow tạo 1 popup window 1280x800. visible=true để debug
// (xem hCaptcha challenge nếu Cloudflare bật challenge thực tế).
func createHiddenWindow(visible bool) (windows.Handle, error) {
	if err := ensureWindowClass(); err != nil {
		return 0, err
	}
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	classNamePtr, _ := windows.UTF16PtrFromString(windowClassName)
	titlePtr, _ := windows.UTF16PtrFromString(windowClassName)

	exStyle := uintptr(wsExNoactivate | wsExToolwindow)
	hwnd, _, cwErr := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(wsPopup),
		0, 0, 1280, 800,
		0, 0, hInstance, 0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("CreateWindowExW: %v", cwErr)
	}
	if visible {
		_, _, _ = procShowWindow.Call(hwnd, swShow)
	} else {
		_, _, _ = procShowWindow.Call(hwnd, swHide)
	}
	return windows.Handle(hwnd), nil
}

func destroyWindow(hwnd windows.Handle) {
	if hwnd != 0 {
		_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
	}
}

// pumpOnce non-blocking: dispatch tối đa 1 message từ queue. Trả true nếu
// có message được dispatch. Dùng trong busy-loop của worker để vừa pump
// vừa quan sát chunks/done channel.
func pumpOnce() bool {
	var m winMsg
	ret, _, _ := procPeekMessageW.Call(
		uintptr(unsafe.Pointer(&m)),
		0, 0, 0, pmRemove,
	)
	if ret == 0 {
		return false
	}
	_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
	_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	return true
}

// pumpUntil chạy message loop cho đến khi cond() trả true hoặc timeout.
// Dùng để chờ async event WV2 (NavigationCompleted, MessageCallback).
// timeout=0 → chờ vô thời hạn.
func pumpUntil(cond func() bool, timeout time.Duration) bool {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		if cond() {
			return true
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		if !pumpOnce() {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// pumpForDuration pump messages liên tục trong khoảng thời gian.
// Dùng giữa các giai đoạn (sleep + dispatch event background).
func pumpForDuration(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !pumpOnce() {
			time.Sleep(5 * time.Millisecond)
		}
	}
}
