// W30 step 1 — Secure Enclave availability probe (plan §3.3/D3,
// owner-to-production §5.1, round-4 evidence discipline).
//
// Standalone by design: no crate deps, compiled on the macOS CI runner
// with plain rustc, linked against Security + CoreFoundation, ad-hoc
// signed (`codesign -s -`) since unsigned binaries may be refused SE
// keygen regardless of SE availability. Prints the RAW OSStatus /
// CFError code so the disposition distinguishes failure MODES:
//   - hardware-absence-shaped failure  -> the VM limitation is CONFIRMED
//   - signing/entitlement-shaped failure -> hypothesis NOT tested
//     (ad-hoc signing may be insufficient for this API) — never record
//     "SE proven absent" on that evidence alone.
// A GREEN result does not auto-start the SE tier — the fold-in stays an
// explicit owner decision (it carries the controller key_origin
// widening). Evidence for that decision is this probe's recorded output.
//
// This file is EVIDENCE TOOLING, never a gate: the workflow runs it
// with `exit 0` and captures the output.
//
// Build: rustc --edition 2021 se_probe.rs -o se_probe \
//          -l framework=Security -l framework=CoreFoundation
// Run:   codesign -s - se_probe && ./se_probe

use std::ffi::CString;
use std::os::raw::{c_char, c_long, c_void};

// ---- CoreFoundation / Security opaque handles -------------------------

type CFStringRef = *const c_void;
type CFTypeRef = *const c_void;
type CFIndex = c_long;
type CFAllocatorRef = *const c_void;
type CFMutableDictionaryRef = *mut c_void;
type CFDictionaryRef = *const c_void;
type CFErrorRef = *const c_void;
type SecKeyRef = *const c_void;

// Opaque extern types for the exported const structs (address-of only —
// the bindgen idiom for callbacks structs passed by pointer).
#[repr(C)]
pub struct CFDictionaryKeyCallBacks {
    _p: [u8; 0],
}
#[repr(C)]
pub struct CFDictionaryValueCallBacks {
    _p: [u8; 0],
}

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

#[link(name = "CoreFoundation")]
extern "C" {
    fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
    fn CFDictionaryCreateMutable(
        allocator: CFAllocatorRef,
        capacity: CFIndex,
        keyCallBacks: *const CFDictionaryKeyCallBacks,
        valueCallBacks: *const CFDictionaryValueCallBacks,
    ) -> CFMutableDictionaryRef;
    fn CFDictionarySetValue(theDict: CFMutableDictionaryRef, key: CFTypeRef, value: CFTypeRef);
    fn CFErrorGetCode(err: CFErrorRef) -> CFIndex;
}

#[link(name = "Security")]
extern "C" {
    static kSecAttrTokenID: CFStringRef;
    static kSecAttrTokenIDSecureEnclave: CFStringRef;
    static kSecAttrKeyType: CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    static kSecPrivateKeyAttrs: CFStringRef;
    fn SecKeyCreateRandomKey(
        parameters: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;
}

fn main() {
    unsafe {
        let null_alloc: CFAllocatorRef = std::ptr::null();
        let top = CFDictionaryCreateMutable(
            null_alloc,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        );
        let priv_attrs = CFDictionaryCreateMutable(
            null_alloc,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        );
        // { kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        //   kSecPrivateKeyAttrs: { kSecAttrKeyType: ECSECPrimeRandom } }
        CFDictionarySetValue(
            top,
            kSecAttrTokenID,
            kSecAttrTokenIDSecureEnclave,
        );
        CFDictionarySetValue(
            priv_attrs,
            kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom,
        );
        CFDictionarySetValue(top, kSecPrivateKeyAttrs, priv_attrs);

        let _utf8_probe = CString::new("utf8").unwrap(); // link-time sanity for c_char use
        let _ = _utf8_probe;

        let mut err: CFErrorRef = std::ptr::null();
        let key = SecKeyCreateRandomKey(top, &mut err);
        if !key.is_null() {
            println!("SE_PROBE=OK");
            println!(
                "detail: SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave, ECDSA P-256) \
                 succeeded - Secure Enclave keygen REACHABLE in this environment"
            );
            println!(
                "note: a GREEN probe never auto-triggers the SE tier - the fold-in is an \
                 explicit owner decision (controller key_origin widening; plan D3)"
            );
            // the key ref intentionally leaks: ephemeral probe process
            std::process::exit(0);
        }
        let code = CFErrorGetCode(err);
        println!("SE_PROBE=FAIL CFError_code={code}");
        // Known-code HINTS for the disposition reader (record-then-read
        // discipline; the raw code above is the evidence of record):
        match code {
            -34018 => println!(
                "hint: -34018 errSecMissingEntitlement - SIGNING/ENTITLEMENT-shaped: \
                 ad-hoc signature insufficient for this API; hypothesis NOT tested \
                 (this is NOT evidence of SE absence)"
            ),
            -50 => println!(
                "hint: -50 errSecParam - parameter-shaped; suspect the probe itself; \
                 hypothesis NOT tested"
            ),
            _ => println!(
                "hint: code unmapped by the probe - record the raw value; compare \
                 against hardware-absence expectations before concluding anything"
            ),
        }
        std::process::exit(2);
    }
}
