#!/usr/bin/env python3
"""
cfox_captcha.py — hCaptcha solver via Camoufox (anti-detect Firefox).
Compiled to cfox_solver.exe via PyInstaller — user never sees this file.

Protocol (stdin/stdout JSON lines):
  stdin  <- {"site_url":"...","site_key":"...","proxy":"user:pass@host:port","headless":true}
  stdout -> {"kind":"info","msg":"..."}
  stdout -> {"kind":"token","token":"P1_xxx..."}
  stdout -> {"kind":"error","error":"..."}
"""
import sys
import json
import os

def emit(kind, **kw):
    msg = {"kind": kind}
    msg.update(kw)
    print(json.dumps(msg, ensure_ascii=False), flush=True)

def ensure_camoufox():
    """Check and install Camoufox browser if needed."""
    try:
        from camoufox.pkgman import installed_verstr
        ver = installed_verstr()
        if ver:
            emit("info", msg=f"Camoufox: {ver}")
            return True
    except Exception:
        pass

    emit("info", msg="Downloading Camoufox browser (~100MB)...")
    try:
        from camoufox.pkgman import install
        install()
        emit("info", msg="Camoufox browser installed")
        return True
    except Exception as e:
        emit("error", error=f"Cannot install Camoufox: {e}")
        return False

def solve_hcaptcha(page, site_key, timeout_ms=90000):
    """
    Solve hCaptcha by clicking the checkbox iframe — giống hệt tool gốc.
    1. Đợi iframe frame=checkbox
    2. Click [role='checkbox']
    3. Đợi token từ document.getElementById('resp').value
    """
    import time

    emit("info", msg="Waiting for hCaptcha iframe...")

    # Đợi iframe checkbox xuất hiện
    checkbox_frame = None
    deadline = time.time() + 30
    while time.time() < deadline:
        for frame in page.frames:
            if 'frame=checkbox' in frame.url:
                checkbox_frame = frame
                break
        if checkbox_frame:
            break
        time.sleep(0.5)

    if not checkbox_frame:
        raise Exception("hCaptcha checkbox iframe not found")

    emit("info", msg="Found checkbox iframe, clicking...")

    # Đợi checkbox visible rồi click
    checkbox = checkbox_frame.locator("[role='checkbox']")
    checkbox.wait_for(state='visible', timeout=10000)
    
    # Giả lập delay con người
    time.sleep(0.5 + __import__('random').random() * 1.0)
    checkbox.click()

    emit("info", msg="Clicked checkbox, waiting for token...")

    # Đợi token
    deadline = time.time() + (timeout_ms / 1000)
    while time.time() < deadline:
        try:
            # Cách tool gốc check
            token = page.evaluate("document.querySelector('textarea[name=\"h-captcha-response\"]')?.value || ''")
            if token:
                return token
        except Exception:
            pass
        time.sleep(0.5)

    raise Exception(f"hCaptcha token timeout ({timeout_ms}ms)")

def main():
    # Read config from stdin
    try:
        raw = sys.stdin.readline().strip()
        if not raw:
            emit("error", error="empty stdin")
            sys.exit(1)
        config = json.loads(raw)
    except Exception as e:
        emit("error", error=f"stdin parse: {e}")
        sys.exit(1)

    site_url = config.get("site_url", "https://elevenlabs.io/")
    site_key = config.get("site_key", "8e58fe8c-1a48-4f94-88ae-8e90b586a192")
    proxy_str = config.get("proxy", "")
    headless = config.get("headless", True)

    # Ensure Camoufox browser
    if not ensure_camoufox():
        sys.exit(1)

    from camoufox import Camoufox

    # Build Camoufox options
    cfox_opts = {"headless": headless}
    if proxy_str:
        if '://' not in proxy_str:
            proxy_str = f"http://{proxy_str}"
        cfox_opts["proxy"] = {"server": proxy_str}
    cfox_opts["geoip"] = True

    emit("info", msg=f"Opening Camoufox (headless={headless})")

    try:
        with Camoufox(**cfox_opts) as browser:
            page = browser.new_page()

            emit("info", msg=f"Navigating to {site_url}")
            page.goto(site_url, wait_until="domcontentloaded", timeout=60000)
            emit("info", msg="Page loaded")

            token = solve_hcaptcha(page, site_key)

            if token:
                emit("info", msg=f"Token len={len(token)}")
                emit("token", token=token)
            else:
                emit("error", error="No token obtained")

            try:
                page.close()
            except Exception:
                pass

    except Exception as e:
        emit("error", error=f"Browser error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
