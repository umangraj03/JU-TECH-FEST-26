from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.dependencies import get_current_principal
from backend.models.schema import Principal, ScenarioDefinition, AgentRunRequest, AgentRunResponse
from backend.agent.scenarios import SCENARIOS, BENIGN_CORPUS
from backend.app.routers.agent import run_agent_workflow

router = APIRouter(prefix="/api/scenarios", tags=["Scenarios"])


@router.get("", response_model=List[ScenarioDefinition])
def get_all_scenarios():
    return SCENARIOS


@router.post("/{scenario_id}/run")
def run_scenario(
    scenario_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db)
):
    sc_map = {s.id: s for s in SCENARIOS}
    if scenario_id not in sc_map:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    target_scenario = sc_map[scenario_id]

    # If scenario requires a specific role to demonstrate correctly, adopt that role for demo fidelity
    acting_principal = principal
    if target_scenario.target_role != principal.role:
        acting_principal = Principal(
            principal_id=f"demo_{target_scenario.target_role}",
            role=target_scenario.target_role,
            name=f"Demo {target_scenario.target_role.title()}"
        )

    if scenario_id == "scenario_6":
        # Run entire suite of benign queries
        benign_results = []
        for prompt in BENIGN_CORPUS[:5]:
            req = AgentRunRequest(message=prompt, scenario_id="scenario_6")
            res = run_agent_workflow(request=req, principal=acting_principal, db=db)
            benign_results.append({
                "prompt": prompt,
                "overall_decision": res.overall_decision,
                "risk_score": res.risk_score,
                "passed": res.overall_decision == "ALLOW"
            })
        all_passed = all(r["passed"] for r in benign_results)
        return {
            "scenario_id": scenario_id,
            "title": target_scenario.title,
            "expected_decision": target_scenario.expected_decision,
            "actual_decision": "ALLOW" if all_passed else "FAIL",
            "passed": all_passed,
            "suite_results": benign_results
        }

    # Run single scenario
    req = AgentRunRequest(
        message=target_scenario.sample_prompt,
        scenario_id=scenario_id
    )
    res = run_agent_workflow(request=req, principal=acting_principal, db=db)

    # Check match with expected
    passed = (res.overall_decision == target_scenario.expected_decision)

    return {
        "scenario_id": scenario_id,
        "title": target_scenario.title,
        "expected_decision": target_scenario.expected_decision,
        "actual_decision": res.overall_decision,
        "passed": passed,
        "result": res.model_dump()
    }
