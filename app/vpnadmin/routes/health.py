from fastapi import APIRouter, Depends

from .. import health as health_data
from ..auth import require_user
from ..models import User

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("/app")
def get_app_health(_: User = Depends(require_user)):
    return health_data.get_app_health()


@router.get("/database")
def get_database_health(_: User = Depends(require_user)):
    return health_data.get_database_health()


@router.get("/host")
def get_host_health(_: User = Depends(require_user)):
    return health_data.get_host_health()


@router.get("/traefik")
def get_traefik_health(_: User = Depends(require_user)):
    return health_data.get_traefik_health()
