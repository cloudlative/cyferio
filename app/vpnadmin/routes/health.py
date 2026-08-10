from fastapi import APIRouter, Depends

from .. import health as health_data
from ..models import User
from ..permissions import require_permission_any_scope

router = APIRouter(prefix="/api/health", tags=["health"])

# System-administration page -- any_scope excludes VPN Self-Service User,
# same reasoning as diagnostics.py's _require_diagnostics_viewer.
_require_health_viewer = require_permission_any_scope("health", "view")


@router.get("/app")
def get_app_health(_: User = Depends(_require_health_viewer)):
    return health_data.get_app_health()


@router.get("/database")
def get_database_health(_: User = Depends(_require_health_viewer)):
    return health_data.get_database_health()


@router.get("/host")
def get_host_health(_: User = Depends(_require_health_viewer)):
    return health_data.get_host_health()


@router.get("/traefik")
def get_traefik_health(_: User = Depends(_require_health_viewer)):
    return health_data.get_traefik_health()
