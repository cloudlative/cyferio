"""
Read-only endpoints backing the City/ASN pick-lists on the Users page's
Login Restrictions panels (see geo_lists.py for how these are built and
cached, and users.html for the cascading country -> city/ASN pickers that
call these). Any authenticated user can read these -- city/ASN names
aren't sensitive, same posture as ISO_3166_COUNTRIES already being
shipped to every logged-in user for the country picker.

Every endpoint here is gated on features.require_feature("geoip") -- see
that module's docstring for why 404, not 403: a direct API call against a
GeoIP endpoint on a deployment that never configured MaxMind should look
exactly like the endpoint doesn't exist, not like a permission problem.
"""
from fastapi import APIRouter, Depends

from .. import geo_lists
from ..features import require_feature
from ..models import User

router = APIRouter(prefix="/api/geo", tags=["geo"])


@router.get("/status")
def get_status(_: User = Depends(require_feature("geoip"))):
    """Whether the city/ASN pick-lists are ready yet, and which (if any)
    are currently (re)building in the background -- see geo_lists.py's
    ensure_fresh. users.html polls this once when a restriction panel
    opens to decide whether to show "still building" instead of an empty
    picker."""
    geo_lists.ensure_fresh()
    return geo_lists.get_status()


@router.get("/countries-with-cities")
def get_countries_with_cities(_: User = Depends(require_feature("geoip"))):
    geo_lists.ensure_fresh()
    return geo_lists.get_countries_with_cities() or []


@router.get("/cities")
def get_cities(country: str, q: str | None = None, _: User = Depends(require_feature("geoip"))):
    """`q` (optional): narrows via the same prefix/substring ranking as
    /asns below. Response is always capped (see geo_lists._MAX_RESULTS) --
    some countries have thousands of cities, and shipping all of them to
    the browser every time (then rendering that many checkboxes) is what
    made this page slow before this endpoint gained search/capping."""
    geo_lists.ensure_fresh()
    result = geo_lists.get_cities(country, q)
    if result is None:
        return {"results": [], "total": 0}
    results, total = result
    return {"results": results, "total": total}


@router.get("/countries-with-asns")
def get_countries_with_asns(_: User = Depends(require_feature("geoip"))):
    geo_lists.ensure_fresh()
    return geo_lists.get_countries_with_asns() or []


@router.get("/asns")
def get_asns(country: str | None = None, q: str | None = None, _: User = Depends(require_feature("geoip"))):
    """No `country` = the "any country" bucket (every known ASN, for
    global operators that don't confidently belong to one place -- see
    geo_lists.py's module docstring). `q` narrows by org name or AS
    number, prefix matches ranked first; response is always capped (see
    geo_lists._MAX_RESULTS) -- "any country" alone is ~78k entries, never
    sent whole to the browser."""
    geo_lists.ensure_fresh()
    result = geo_lists.get_asns(country, q)
    if result is None:
        return {"results": [], "total": 0}
    results, total = result
    return {"results": results, "total": total}
