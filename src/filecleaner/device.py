"""iOS device management over USB: list installed apps, uninstall selected ones.

UNVERIFIED: written without a physical iPhone/iPad available to test
against. Every device interaction requires the device to be plugged in,
unlocked, and paired ("Trust This Computer?") — a step only the device's
owner can complete by tapping the prompt on the phone itself, so this
could not be exercised end-to-end while building it. pymobiledevice3's
device APIs are asyncio-based (confirmed while building this — every
public function here wraps that in `asyncio.run`), but the actual protocol
exchange with a live device is still unverified. Treat this as a first
draft to validate against a real device before relying on it.

Built on pymobiledevice3 (pure-Python, pip-installable — no Homebrew/
libimobiledevice system dependency needed; install with `pip install
filecleaner[device]`). Local device communication only over USB; nothing
here makes a network call.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


class DeviceUnavailable(Exception):
    """No device connected, or pairing/trust hasn't been completed yet."""


@dataclass
class DeviceInfo:
    udid: str
    name: str
    product_type: str


@dataclass
class AppInfo:
    bundle_id: str
    name: str
    version: str
    size_bytes: int


def _friendly_error(exc: Exception) -> str:
    try:
        from pymobiledevice3 import exceptions as pmd_exc
    except ImportError:
        return str(exc)

    if isinstance(exc, pmd_exc.NoDeviceConnectedError):
        return "No iPhone/iPad detected. Plug it in with a cable and unlock it."
    if isinstance(
        exc,
        (
            pmd_exc.NotTrustedError,
            pmd_exc.UserDeniedPairingError,
            pmd_exc.PairingDialogResponsePendingError,
            pmd_exc.NotPairedError,
            pmd_exc.FatalPairingError,
        ),
    ):
        return (
            "Device found but not paired yet. Unlock it and tap 'Trust This Computer' "
            "when the prompt appears on the device, then try again."
        )
    if isinstance(exc, pmd_exc.PasswordRequiredError):
        return "Device is locked. Unlock it with its passcode, then try again."
    return f"Could not talk to the device: {exc}"


def _require_pymobiledevice3() -> None:
    try:
        import pymobiledevice3  # noqa: F401
    except ImportError as exc:
        raise DeviceUnavailable(
            "pymobiledevice3 isn't installed. Run `pip install filecleaner[device]` (or "
            "`.venv/bin/pip install pymobiledevice3` in this project's venv)."
        ) from exc


async def _list_devices_async() -> list[DeviceInfo]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.usbmux import list_devices as list_mux_devices

    mux_devices = await list_mux_devices()
    devices: list[DeviceInfo] = []
    for mux in mux_devices:
        lockdown = await create_using_usbmux(serial=mux.serial, autopair=False)
        info = lockdown.short_info
        devices.append(
            DeviceInfo(
                udid=info.get("UniqueDeviceID") or mux.serial,
                name=info.get("DeviceName") or mux.serial,
                product_type=info.get("ProductType") or "",
            )
        )
    return devices


def list_devices() -> list[DeviceInfo]:
    _require_pymobiledevice3()
    try:
        return asyncio.run(_list_devices_async())
    except Exception as exc:
        raise DeviceUnavailable(_friendly_error(exc)) from exc


async def _list_apps_async(udid: str | None, user_apps_only: bool) -> list[AppInfo]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    lockdown = await create_using_usbmux(serial=udid, autopair=False)
    service = InstallationProxyService(lockdown=lockdown)
    await service.connect()
    apps = await service.get_apps(
        application_type="User" if user_apps_only else "Any",
        calculate_sizes=True,
    )

    result: list[AppInfo] = []
    for bundle_id, info in apps.items():
        size = int(info.get("DynamicDiskUsage", 0) or 0) + int(info.get("StaticDiskUsage", 0) or 0)
        result.append(
            AppInfo(
                bundle_id=bundle_id,
                name=info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle_id,
                version=info.get("CFBundleShortVersionString", ""),
                size_bytes=size,
            )
        )
    return result


def list_apps(udid: str | None = None, *, user_apps_only: bool = True) -> list[AppInfo]:
    _require_pymobiledevice3()
    try:
        return asyncio.run(_list_apps_async(udid, user_apps_only))
    except Exception as exc:
        raise DeviceUnavailable(_friendly_error(exc)) from exc


async def _uninstall_app_async(bundle_id: str, udid: str | None) -> None:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    lockdown = await create_using_usbmux(serial=udid, autopair=False)
    service = InstallationProxyService(lockdown=lockdown)
    await service.connect()
    await service.uninstall(bundle_id)


def uninstall_app(bundle_id: str, udid: str | None = None) -> None:
    _require_pymobiledevice3()
    try:
        asyncio.run(_uninstall_app_async(bundle_id, udid))
    except Exception as exc:
        raise DeviceUnavailable(_friendly_error(exc)) from exc
