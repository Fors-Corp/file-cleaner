from filecleaner import device


def test_list_devices_returns_empty_when_none_connected():
    # This machine has no iOS device attached during tests — exercises the
    # real pymobiledevice3 usbmux call end-to-end (asyncio wiring included)
    # without needing a physical device.
    assert device.list_devices() == []


def test_list_apps_raises_device_unavailable_when_none_connected():
    try:
        device.list_apps()
    except device.DeviceUnavailable as exc:
        assert "No iPhone/iPad detected" in str(exc)
    else:
        raise AssertionError("expected DeviceUnavailable when no device is connected")


def test_friendly_error_maps_no_device_connected():
    from pymobiledevice3 import exceptions as pmd_exc

    msg = device._friendly_error(pmd_exc.NoDeviceConnectedError())
    assert "Plug it in" in msg


def test_friendly_error_maps_trust_required():
    from pymobiledevice3 import exceptions as pmd_exc

    msg = device._friendly_error(pmd_exc.NotTrustedError())
    assert "Trust This Computer" in msg


def test_friendly_error_falls_back_for_unknown_exception():
    msg = device._friendly_error(RuntimeError("something else"))
    assert "something else" in msg
