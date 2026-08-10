"""
Read-only endpoints backing the City/ASN pick-lists on the Users page's
Login Restrictions panels (see geo_lists.py for how these are built and
cached, and users.html for the cascading country -> city/ASN pickers that
call these). Any authenticated user can read these -- city/ASN names
aren't sensitive, same posture as ISO_3166_COUNTRIES already being
shipped to every logged-in user for the country picker.
"""
from fastapi import APIRouter, Depends

from .. import geo_lists
from ..auth import require_user
from ..models import User

router = APIRouter(prefix="/api/geo", tags=["geo"])


@router.get("/status")
def get_status(_: User = Depends(require_user)):
    """Whether the city/ASN pick-lists are ready yet, and which (if any)
    are currently (re)building in the background -- see geo_lists.py's
    ensure_fresh. users.html polls this once when a restriction panel
    opens to decide whether to show "still building" instead of an empty
    picker."""
    geo_lists.ensure_fresh()
    return geo_lists.get_status()


@router.get("/countries-with-cities")
def get_countries_with_cities(_: User = Depends(require_user)):
    geo_lists.ensure_fresh()
    return geo_lists.get_countries_with_cities() or []


@router.get("/cities")
def get_cities(country: str, _: User = Depends(require_user)):
    geo_lists.ensure_fresh()
    return geo_lists.get_cities(country) or []


@router.get("/countries-with-asns")
def get_countries_with_asns(_: User = Depends(require_user)):
    geo_lists.ensure_fresh()
    return geo_lists.get_countries_with_asns() or []


@router.get("/asns")
def get_asns(country: str | None = None, _: User = Depends(require_user)):
    """No `country` = the "any country" bucket (every known ASN, for
    global operators that don't confidently belong to one place -- see
    geo_lists.py's module docstring)."""
    geo_lists.ensure_fresh()
    return geo_lists.get_asns(country) or []
