from backend.app.routers.agent import router as agent_router
from backend.app.routers.stats import router as stats_router
from backend.app.routers.policy import router as policy_router
from backend.app.routers.approvals import router as approvals_router
from backend.app.routers.audit import router as audit_router
from backend.app.routers.scenarios import router as scenarios_router
from backend.app.routers.demo import router as demo_router

__all__ = [
    "agent_router",
    "stats_router",
    "policy_router",
    "approvals_router",
    "audit_router",
    "scenarios_router",
    "demo_router",
]
