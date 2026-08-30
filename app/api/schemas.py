"""Request and response models shared across the API routers."""

from typing import List, Literal, Optional

from ninja import Schema


class ErrorOut(Schema):
    """Every non-2xx response on this API is shaped like this."""

    error: str


class MessageOut(Schema):
    message: str


class SubmitFQDNIn(Schema):
    fqdn_list: List[str]


class UpdateEDLIn(Schema):
    auto_url: str
    fqdn_list: List[str]
    command: Literal['update', 'overwrite'] = 'update'


class BootVersionOut(Schema):
    boot_version: str
    disk_version: str


class UserIdCheckinIn(Schema):
    """Heartbeat from a managed browser reporting who is signed in.

    The IP is deliberately absent. It is taken from the connection as the
    server observes it, so a client cannot claim an address it does not have.
    """

    username: str
    device_id: Optional[str] = ''
    agent_version: Optional[str] = ''
    chrome_version: Optional[str] = ''


class UserIdConfigOut(Schema):
    """Runtime settings the extension re-reads on every check-in.

    Shipping these from the server means changing a heartbeat interval does
    not require repackaging and redeploying the extension to every device.
    """

    enabled: bool
    heartbeat_seconds: int
    jitter_seconds: int


class UserIdCheckinOut(UserIdConfigOut):
    status: str
