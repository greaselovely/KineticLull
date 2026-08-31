"""Vendor dispatch for firewall operations.

Only PAN-OS is implemented. This exists so that adding a manufacturer means
writing a module with the same three entrypoints and adding one line here,
rather than editing every caller. Other vendors that consume EDLs (Fortinet
and friends) are the reason the `Firewall.vendor` column exists.

A driver module must provide:
    push_user_id_mappings(mappings, firewall, timeout_minutes) -> (bool, str)
    test_connection(firewall)                                  -> (bool, str)
    curl_equivalent(firewall)                                  -> str
"""

from app import panos
from app.models import Firewall


class UnsupportedVendor(Exception):
    pass


_DRIVERS = {
    Firewall.VENDOR_PANOS: panos,
}


def driver_for(firewall):
    """Return the driver module for a firewall, or raise UnsupportedVendor."""
    driver = _DRIVERS.get(firewall.vendor)
    if driver is None:
        raise UnsupportedVendor(
            f'No driver for vendor {firewall.vendor!r} on firewall {firewall.name!r}.'
        )
    return driver


def userid_push_targets():
    """Every enabled firewall that should receive User-ID mappings.

    The union of firewalls flagged individually and those in the group
    nominated in settings. Both exist because one box and a whole site are
    different questions, and neither should require expressing the other.
    """
    from django.db.models import Q

    from app.models import AppSettings

    app_settings = AppSettings.objects.filter(pk=1).first()
    group = app_settings.userid_push_group if app_settings else None

    targets = Q(receives_user_id=True)
    if group is not None:
        targets |= Q(groups=group)

    return Firewall.objects.filter(enabled=True).filter(targets).distinct()
