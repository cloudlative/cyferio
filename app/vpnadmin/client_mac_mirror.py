"""Keeps models.ClientMac (a queryable DB mirror of openvpn_db.txt) in
sync with the flat file, which stays the real connect-time enforcement
source -- see that model's own docstring for why.

Two ways this table gets updated:
  1. record_mac_added/record_mac_removed -- called by routes/clients.py
     and routes/me_vpn.py right after their existing cli.add_mac/
     cli.remove_mac calls succeed, so the mirror only ever reflects a
     write the file itself already has.
  2. resync_client_macs -- a full reconciliation against
     cli_wrapper.dump_macs() (openvpn-install.sh's --dump-macs), run once
     at every startup (main.py's lifespan()) to repair any drift from the
     file being touched outside the app (hand edits, SSH, setup.sh
     provisioning) and to backfill this table on first upgrade."""
from sqlalchemy.orm import Session

from .models import ClientMac


def record_mac_added(db: Session, vpn_client_name: str, mac: str) -> None:
    mac = mac.strip().lower()
    exists = (
        db.query(ClientMac)
        .filter(ClientMac.vpn_client_name == vpn_client_name, ClientMac.mac == mac)
        .first()
    )
    if exists is not None:
        return  # already mirrored -- e.g. a resync beat this call to it
    db.add(ClientMac(vpn_client_name=vpn_client_name, mac=mac))
    db.commit()


def record_mac_removed(db: Session, vpn_client_name: str, mac: str) -> None:
    mac = mac.strip().lower()
    db.query(ClientMac).filter(
        ClientMac.vpn_client_name == vpn_client_name, ClientMac.mac == mac
    ).delete(synchronize_session=False)
    db.commit()


def resync_client_macs(db: Session, current: dict[str, list[str]]) -> None:
    """`current` is openvpn_db.txt's full contents, as returned by
    cli_wrapper.dump_macs() -- {vpn_client_name: [mac, ...]}. Makes
    ClientMac exactly match: deletes any mirrored row no longer in the
    file, inserts any file entry not yet mirrored. Cheap at this app's
    scale (one full table read + one dict diff, no per-row shelling), and
    correct even if this is the very first run (empty table -> full
    backfill) or the file was hand-edited (drift -> corrected)."""
    wanted: set[tuple[str, str]] = {
        (name, mac.strip().lower()) for name, macs in current.items() for mac in macs
    }
    existing_rows = db.query(ClientMac).all()
    existing: dict[tuple[str, str], ClientMac] = {(r.vpn_client_name, r.mac): r for r in existing_rows}

    for key, row in existing.items():
        if key not in wanted:
            db.delete(row)
    for name, mac in wanted:
        if (name, mac) not in existing:
            db.add(ClientMac(vpn_client_name=name, mac=mac))
    db.commit()
