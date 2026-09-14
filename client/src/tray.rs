//! W13 step 4 [ADR-0007 resolved: Win32 tray — see the amended ADR]: the
//! tray is a PURE SERVICE CLIENT — a message-only window + Shell_NotifyIcon
//! that renders the service's IPC state and issues IPC commands. It never
//! links engine logic (the one-shared-engine contract).
//!
//! Automation contract (review r2): the icon tooltip IS the state and doubles
//! as the UIA `Name` ("aZTNA — Connected" etc.); menu item labels are FIXED
//! strings. The e2e suite asserts the data path through the same IPC the
//! tray drives; visual rendering is the owner-run checklist item (a GUI
//! pixel assert is not toolable in this harness — documented limitation).

use crate::svc;
use anyhow::Result;

const WM_APP_TRAY: u32 = 0x8000; // WM_APP
const TRAY_ID: u32 = 1;

// Fixed menu labels (automation contract — do not rename)
const MENU_CONNECT: u32 = 4001;
const MENU_DISCONNECT: u32 = 4002;
const MENU_EXIT: u32 = 4003;
const MENU_DIAG: u32 = 4004;

struct TrayState {
    last_state: String,
    ipc_bind: String,
}

// tray state accessed only from the tray's own thread + the poller task
// (sync via the message loop's single-threaded ownership); UnsafeCell
// avoids the static_mut_ref lint without pretending thread safety.
static TRAY: std::sync::atomic::AtomicPtr<TrayState> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

fn tray() -> &'static mut TrayState {
    let p = TRAY.load(std::sync::atomic::Ordering::SeqCst);
    unsafe { p.as_mut().unwrap() }
}

fn tray_store(st: TrayState) {
    let boxed = Box::into_raw(Box::new(st));
    TRAY.store(boxed, std::sync::atomic::Ordering::SeqCst);
}

fn tip_for(state: &str) -> String {
    // The UIA Name contract: stable "aZTNA — <state>" tooltip
    format!("aZTNA - {state}")
}

pub fn run_tray(ipc_bind: Option<String>) -> Result<()> {
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::*;

    let bind = ipc_bind.unwrap_or_else(|| {
        svc::load_config()
            .map(|c| c.ipc_bind)
            .unwrap_or("127.0.0.1:29171".into())
    });
    tray_store(TrayState {
        last_state: String::new(),
        ipc_bind: bind,
    });

    unsafe {
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        let hinstance = GetModuleHandleW(None)?;
        let class_name = w!("aztna_tray_wnd");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance.into(),
            lpszClassName: class_name,
            ..Default::default()
        };
        let atom = RegisterClassW(&wc);
        if atom == 0 {
            return Err(anyhow::anyhow!("RegisterClassW failed"));
        }
        // message-only window: no visual surface, receives tray callbacks
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("aztna-tray"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            None,
            Some(&hinstance.into()),
            None,
        )?;
        add_icon(hwnd, "aZTNA - starting");

        // status poller: drives tooltip/balloon from the service IPC
        let poller = tokio::spawn(async move {
            loop {
                if let Ok(r) = svc::ipc_call(
                    &tray().ipc_bind,
                    &svc::IpcReq {
                        v: 1,
                        cmd: "status".into(),
                        token: None,
                    },
                )
                .await
                {
                    if r.state != tray().last_state {
                        let (state, note) = (r.state.clone(), r.state.clone());
                        tray().last_state = state;
                        update_tooltip(note);
                    }
                } else if tray().last_state != "unreachable" {
                    tray().last_state = "unreachable".into();
                    update_tooltip("unreachable".into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });

        // Win32 message loop (blocking — the tray's own thread of control)
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        poller.abort();
        Ok(())
    }
}

unsafe fn add_icon(hwnd: windows::Win32::Foundation::HWND, tip: &str) {
    use windows::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NOTIFYICONDATAW,
    };
    use windows::Win32::UI::WindowsAndMessaging::LoadIconW;
    let mut nid = NOTIFYICONDATAW {
        hWnd: hwnd,
        uID: TRAY_ID,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_APP_TRAY,
        hIcon: LoadIconW(None, windows::core::PCWSTR(32512 as *const _)).unwrap_or_default(),
        ..Default::default()
    };
    let tip_w: Vec<u16> = tip.encode_utf16().take(127).collect();
    for (i, c) in tip_w.iter().enumerate() {
        nid.szTip[i] = *c;
    }
    let _ = Shell_NotifyIconW(NIM_ADD, &nid);
}

unsafe fn update_tooltip(state: String) {
    use windows::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_INFO, NIF_TIP, NIM_MODIFY, NOTIFYICONDATAW,
    };
    let hwnd = find_hwnd();
    let Some(hwnd) = hwnd else { return };
    let mut nid = NOTIFYICONDATAW {
        hWnd: hwnd,
        uID: TRAY_ID,
        uFlags: NIF_TIP | NIF_INFO,
        ..Default::default()
    };
    let tip = tip_for(&state);
    let tip_w: Vec<u16> = tip.encode_utf16().take(127).collect();
    for (i, c) in tip_w.iter().enumerate() {
        nid.szTip[i] = *c;
    }
    let info: Vec<u16> = format!("aZTNA is {state}")
        .encode_utf16()
        .take(254)
        .collect();
    for (i, c) in info.iter().enumerate() {
        nid.szInfo[i] = *c;
    }
    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    crate::log_event("tray_state_changed", &format!("tray={state}"));
}

unsafe fn find_hwnd() -> Option<windows::Win32::Foundation::HWND> {
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
    FindWindowW(w!("aztna_tray_wnd"), None).ok()
}

unsafe extern "system" fn wnd_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::LRESULT;
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, DefWindowProcW, DestroyMenu, GetCursorPos, PostQuitMessage,
        SetForegroundWindow, TrackPopupMenu, TPM_BOTTOMALIGN, TPM_RETURNCMD, TPM_RIGHTALIGN,
        TPM_RIGHTBUTTON, WM_LBUTTONDBLCLK, WM_RBUTTONUP,
    };
    if msg == WM_APP_TRAY {
        // tray callback: LOWORD(lparam) = event
        let event = (lparam.0 as u32) & 0xFFFF;
        if event == WM_RBUTTONUP {
            // fixed-label context menu (automation contract)
            let Ok(menu) = CreatePopupMenu() else {
                return LRESULT(0);
            };
            let mut items: Vec<(u32, &str)> =
                vec![(MENU_CONNECT, "Connect"), (MENU_DISCONNECT, "Disconnect")];
            items.push((MENU_EXIT, "Exit"));
            for (id, label) in &items {
                let w: Vec<u16> = label.encode_utf16().chain(std::iter::once(0)).collect();
                let _ = AppendMenuW(
                    menu,
                    windows::Win32::UI::WindowsAndMessaging::MF_STRING,
                    *id as usize,
                    windows::core::PCWSTR(w.as_ptr()),
                );
            }
            let mut pt = windows::Win32::Foundation::POINT::default();
            let _ = GetCursorPos(&mut pt);
            let _ = SetForegroundWindow(hwnd);
            let cmd = TrackPopupMenu(
                menu,
                TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_RIGHTALIGN | TPM_RETURNCMD,
                pt.x,
                pt.y,
                0,
                hwnd,
                None,
            );
            let _ = DestroyMenu(menu);
            if cmd.0 != 0 {
                menu_command(cmd.0 as u32);
            }
            return LRESULT(0);
        } else if event == WM_LBUTTONDBLCLK {
            menu_command(MENU_CONNECT);
            return LRESULT(0);
        }
        return LRESULT(0);
    }
    if msg == 0x0002 {
        PostQuitMessage(0);
        return LRESULT(0);
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

fn menu_command(cmd: u32) {
    let bind = tray().ipc_bind.clone();
    match cmd {
        MENU_CONNECT => {
            if let Err(e) = futures_execute(svc::ipc_call(
                &bind,
                &svc::IpcReq {
                    v: 1,
                    cmd: "connect".into(),
                    token: None,
                },
            )) {
                crate::log_event("tray_cmd_failed", &format!("connect: {e:#}"));
            }
        }
        MENU_DISCONNECT => {
            if let Err(e) = futures_execute(svc::ipc_call(
                &bind,
                &svc::IpcReq {
                    v: 1,
                    cmd: "disconnect".into(),
                    token: None,
                },
            )) {
                crate::log_event("tray_cmd_failed", &format!("disconnect: {e:#}"));
            }
        }
        MENU_EXIT => unsafe {
            if let Some(hwnd) = find_hwnd() {
                let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
            }
        },
        _ => {}
    }
}

// tiny block_on helper: menu callbacks run on the Win32 thread, off the
// tokio runtime — execute the future on a fresh single-thread runtime
fn futures_execute<F: std::future::Future<Output = Result<svc::IpcResp>>>(
    fut: F,
) -> Result<svc::IpcResp> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(fut)
}
