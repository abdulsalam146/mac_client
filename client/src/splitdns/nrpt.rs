//! W43 S3: the Windows NRPT channel — in-process WMI/CIM, no powershell.exe
//! (owner decision D2, verified by the S3-pre probe).
//!
//! Everything here is MEASURED behavior of `root\Microsoft\Windows\Dns`
//! (see `docs/spikes/S3-pre-d2-d5-probe-findings.md`):
//! - `PS_DnsClientNrptRule` methods class; `MSFT_DNSClientNRPTRule` is NOT
//!   queryable — enumeration is the `Get` method's `cmdletOutput`
//!   (`VT_ARRAY|VT_UNKNOWN` of embedded `DnsClientNrptRule` objects).
//! - `Add(Namespace: string[], NameServers: string[], Comment: string, ...)`
//!   — arrays REJECTED as scalars (TYPE_MISMATCH).
//! - `Remove(Name: the rule's GUID, Force)` — the namespace is NOT the key.
//! - Writes need elevation (LocalSystem service context); reads work
//!   unelevated.
//!
//! All calls are SYNCHRONOUS COM — callers run them off the async runtime
//! (`spawn_blocking`) and enforce the plan §9 2 s timeout + one retry.

use anyhow::{anyhow, Context, Result};

use windows::core::{BSTR, PCWSTR, VARIANT};
use windows::Win32::System::Com::{
    CoCreateInstance, CoSetProxyBlanket, CLSCTX_INPROC_SERVER, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::InitVariantFromStringArray;
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
};

const DNS_NS: &str = r"root\Microsoft\Windows\Dns";
const CLASS: &str = "PS_DnsClientNrptRule";
/// Rules only ever steer to the loopback resolver — never a remote address
/// (plan §4.2). The zone forwarders bind the mapped IP on the destination
/// port; the resolver itself is always loopback:53.
pub const NAMESERVER: &str = "127.0.0.1";

#[derive(Debug, Clone, PartialEq)]
pub struct NrptRule {
    pub namespace: String,
    pub comment: String,
    /// The rule's Name GUID — the ONLY value Remove accepts.
    pub guid: String,
}

unsafe fn connect() -> Result<IWbemServices> {
    // COM init on this thread (idempotent); the wmi crate's RAII wrapper.
    let _com = wmi::COMLibrary::new().map_err(|e| anyhow!("CoInitialize: {:?}", e))?;
    let loc: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
        .map_err(|e| anyhow!("{:?}", e))?;
    let path = BSTR::from(DNS_NS);
    let empty = BSTR::new();
    let svc = loc
        .ConnectServer(
            &path,
            &empty,
            &empty,
            &empty,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
            &empty,
            None,
        )
        .map_err(|e| anyhow!("ConnectServer({}): {:?}", DNS_NS, e))?;
    CoSetProxyBlanket(
        &svc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        None,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        None,
        EOAC_NONE,
    )
    .map_err(|e| anyhow!("CoSetProxyBlanket: {:?}", e))?;
    Ok(svc)
}

enum Val {
    Str(String),
    StrArray(Vec<String>),
}

/// Execute a `PS_DnsClientNrptRule` method with the measured parameter
/// shapes. Returns the out-params object when the method produces one.
unsafe fn exec_method(
    svc: &IWbemServices,
    method: &str,
    params: &[(&str, Val)],
) -> Result<Option<IWbemClassObject>> {
    let class_path = BSTR::from(CLASS);
    let mut class_def = None;
    svc.GetObject(
        &class_path,
        Default::default(),
        None,
        Some(&mut class_def),
        None,
    )
    .map_err(|e| anyhow!("GetObject({}): {:?}", CLASS, e))?;
    let class_def: IWbemClassObject = class_def.ok_or_else(|| anyhow!("empty class def"))?;
    let method_name = BSTR::from(method);
    let mut in_sig = None;
    class_def
        .GetMethod(
            &method_name,
            Default::default(),
            &mut in_sig,
            std::ptr::null_mut(),
        )
        .with_context(|| format!("GetMethod({}) — method missing from provider", method))?;
    let inst = match in_sig {
        Some(sig) => {
            let inst = sig
                .SpawnInstance(Default::default())
                .map_err(|e| anyhow!("SpawnInstance: {:?}", e))?;
            for (name, val) in params {
                let v = match val {
                    Val::Str(s) => VARIANT::from(s.as_str()),
                    Val::StrArray(items) => {
                        let owned: Vec<Vec<u16>> = items
                            .iter()
                            .map(|s| {
                                let mut w: Vec<u16> = s.encode_utf16().collect();
                                w.push(0);
                                w
                            })
                            .collect();
                        let wide: Vec<PCWSTR> = owned.iter().map(|w| PCWSTR(w.as_ptr())).collect();
                        InitVariantFromStringArray(&wide)
                            .map_err(|e| anyhow!("InitVariantFromStringArray({}): {:?}", name, e))?
                    }
                };
                inst.Put(
                    &windows::core::HSTRING::from(*name),
                    Default::default(),
                    &v,
                    0,
                )
                .with_context(|| format!("Put({}) — parameter shape rejected by provider", name))?;
            }
            Some(inst)
        }
        None => None,
    };
    let mut out = None;
    svc.ExecMethod(
        &class_path,
        &method_name,
        Default::default(),
        None,
        inst.as_ref(),
        Some(&mut out),
        None,
    )
    .with_context(|| format!("ExecMethod({})", method))?;
    Ok(out)
}

/// Enumerate all NRPT rules through the `Get` method's `cmdletOutput`.
/// Works unelevated (read path). Empty host ⇒ empty vec.
pub fn enumerate() -> Result<Vec<NrptRule>> {
    // S3-pre discipline: WMI COM calls run on a thread without a tokio
    // context requirement, but this fn is sync — callers wrap it.
    unsafe {
        let svc = connect()?;
        let out = exec_method(&svc, "Get", &[])?;
        let out = match out {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        let mut v = VARIANT::default();
        if out
            .Get(&BSTR::from("cmdletOutput"), 0, &mut v, None, None)
            .is_err()
        {
            return Ok(Vec::new());
        }
        unwrap_cmdlet_output(&v)
    }
}

// ABI mirror of VARIANT (windows-core hides the interior; this is the
// stable OLE layout: 8-byte header, then a 16-byte union whose first
// pointer-sized slot is parray for SAFEARRAY-backed values).
#[repr(C)]
struct RawVariantHeader {
    vt: u16,
    _r: [u16; 3],
    value: [u64; 2],
}

unsafe fn unwrap_cmdlet_output(v: &VARIANT) -> Result<Vec<NrptRule>> {
    use windows::core::Interface;
    use windows::Win32::System::Com::SAFEARRAY;
    use windows::Win32::System::Variant::{VT_ARRAY, VT_UNKNOWN};

    let raw = v as *const VARIANT as *const RawVariantHeader;
    if (*raw).vt != (VT_ARRAY.0 | VT_UNKNOWN.0) {
        return Ok(Vec::new());
    }
    let arr = (*raw).value[0] as *const SAFEARRAY;
    if arr.is_null() {
        return Ok(Vec::new());
    }
    let count = (*arr).rgsabound[0].cElements as usize;
    let data = (*arr).pvData as *const *mut core::ffi::c_void;
    let mut rules = Vec::with_capacity(count);
    for i in 0..count {
        // Refcount discipline (the S3-pre probe bug): from_raw claims a
        // refcount the SAFEARRAY still owns — forget the borrowed handle and
        // release only the cast's own AddRef.
        let unk = windows::core::IUnknown::from_raw(std::ptr::read(data.add(i)));
        let obj: IWbemClassObject = match unk.cast() {
            Ok(o) => o,
            Err(e) => {
                std::mem::forget(unk);
                return Err(anyhow!("cmdletOutput element cast: {:?}", e));
            }
        };
        std::mem::forget(unk);
        let getstr = |prop: &str| -> String {
            let mut pv = VARIANT::default();
            // &BSTR keeps the buffer alive for the duration of the call
            // (a returned PCWSTR into a dropped temporary would be UB)
            if obj.Get(&BSTR::from(prop), 0, &mut pv, None, None).is_ok() {
                format!("{}", pv)
            } else {
                String::new()
            }
        };
        rules.push(NrptRule {
            namespace: getstr("Namespace"),
            comment: getstr("Comment"),
            guid: getstr("Name"),
        });
    }
    Ok(rules)
}

/// Install one exact-namespace rule routing to the loopback resolver, with
/// the ownership tag in the Comment. Requires elevation (the LocalSystem
/// service context) — the caller refuses auto mode without it.
pub fn add(namespace: &str, comment: &str) -> Result<()> {
    unsafe {
        let svc = connect()?;
        exec_method(
            &svc,
            "Add",
            &[
                ("Namespace", Val::StrArray(vec![namespace.to_string()])),
                ("NameServers", Val::StrArray(vec![NAMESERVER.to_string()])),
                ("Comment", Val::Str(comment.to_string())),
            ],
        )?;
        Ok(())
    }
}

/// Remove one rule by its Name GUID (the measured deletion key).
pub fn remove(guid: &str) -> Result<()> {
    unsafe {
        let svc = connect()?;
        exec_method(&svc, "Remove", &[("Name", Val::Str(guid.to_string()))])?;
        Ok(())
    }
}

/// WBEM_E_ACCESS_DENIED (0x80041003) / E_ACCESSDENIED (0x80070005) — the
/// unelevated-write signature the caller uses to refuse auto mode (or
/// surface a clear error) instead of retrying forever.
pub fn err_is_access_denied(e: &anyhow::Error) -> bool {
    let s = format!("{:#}", e).to_lowercase();
    s.contains("80041003")
        || s.contains("80070005")
        || s.contains("-2145588093")
        || s.contains("-2147024891")
        || s.contains("access is denied")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live smoke (read path only, unelevated): enumerate never errors on a
    /// healthy host — the write paths need elevation and are covered by the
    /// W43S3 lane, not unit tests.
    #[test]
    fn enumerate_live_smoke() {
        let rules = enumerate().expect("enumerate must work unelevated");
        // A dev box under test may carry probe rules; a clean box has none.
        // Both are fine — the invariant is the call itself succeeding.
        for r in &rules {
            assert!(!r.namespace.is_empty() || !r.guid.is_empty());
        }
    }

    #[test]
    fn access_denied_detector() {
        let e = anyhow!("ExecMethod(Add): Error {{ code: HRESULT(0x80041003) }}");
        assert!(err_is_access_denied(&e));
        let e2 = anyhow!("some other failure 0x80041005");
        assert!(!err_is_access_denied(&e2));
    }
}
