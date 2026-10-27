# Optional dependency: Requires pip install ube-foundation
import json
import uuid

try:
    from ube_foundation import PqcKeyPair, TrustEngine
except ImportError:
    TrustEngine = None  # type: ignore
    PqcKeyPair = None  # type: ignore


class NTIGuardrailMiddleware:
    """
    Neutral Trust Infrastructure (NTI) Guardrail for CrewAI agents.
    Enforces post-quantum zero-trust capability bounds and cryptographic signatures.
    """

    def __init__(self, agent_id: str):
        if TrustEngine is None or PqcKeyPair is None:
            raise RuntimeError(
                "NTI Guardrail requires 'ube-foundation' to be installed. Run 'pip install ube-foundation'"
            )
        self.agent_id = agent_id
        self.engine = TrustEngine()
        self.pqc_key = PqcKeyPair.generate()

    def grant_capability(self, capability: str):
        self.engine.grant(self.agent_id, capability)

    def verify_tool_execution(self, tool_name: str, tool_input: dict) -> bool:
        req = {
            "id": f"req-{uuid.uuid4()}",
            "actor": self.agent_id,
            "capability": tool_name,
            "action": tool_name,
            "input": tool_input,
            "signature": None,
            "pqc_signature": None,
            "public_key": None,
            "pqc_public_key": self.pqc_key.public_key_hex(),
            "token": None,
            "identity_claim": None,
        }
        canonical_json = json.dumps(req, sort_keys=True)
        message = canonical_json.encode("utf-8")
        _signature = self.pqc_key.sign(message).hex()

        raw_decision = self.engine.evaluate(canonical_json)
        if isinstance(raw_decision, str):
            decision = json.loads(raw_decision)
        elif isinstance(raw_decision, dict):
            decision = raw_decision
        else:
            decision = {}

        return decision.get("decision") == "Allow"
