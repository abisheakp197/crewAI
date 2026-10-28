import json
import socket
from unittest.mock import MagicMock, patch

import pytest

from crewai.agents.parser import AgentAction
from crewai.security import NTIGuardrailMiddleware
import crewai.security.nti_guardrail as nti_module
from crewai.tools.structured_tool import CrewStructuredTool
from crewai.utilities.tool_utils import execute_tool_and_check_finality


def test_nti_guardrail_export():
    """Verify NTIGuardrailMiddleware is exported in crewai.security."""
    from crewai.security import __all__ as security_all

    assert "NTIGuardrailMiddleware" in security_all
    assert NTIGuardrailMiddleware is nti_module.NTIGuardrailMiddleware


def test_nti_guardrail_missing_dependency():
    """Verify RuntimeError is raised when ube_foundation is not installed."""
    with patch.object(nti_module, "TrustEngine", None), patch.object(
        nti_module, "PqcKeyPair", None
    ):
        with pytest.raises(
            RuntimeError,
            match="NTI Guardrail requires 'ube-foundation' to be installed.",
        ):
            nti_module.NTIGuardrailMiddleware("agent_123")


def test_nti_guardrail_key_persistence_and_no_mutation():
    """Verify PqcKeyPair is generated once in __init__ and payload is not mutated."""
    mock_pqc_key = MagicMock()
    mock_pqc_key.public_key_hex.return_value = "pubkey_hex_123"
    mock_pqc_key.sign.return_value = b"signature_bytes"

    mock_pqc_cls = MagicMock()
    mock_pqc_cls.generate.return_value = mock_pqc_key

    mock_engine = MagicMock()
    mock_engine.evaluate.return_value = json.dumps({"decision": "Allow"})
    mock_engine_cls = MagicMock(return_value=mock_engine)

    with patch.object(nti_module, "PqcKeyPair", mock_pqc_cls), patch.object(
        nti_module, "TrustEngine", mock_engine_cls
    ):
        middleware = nti_module.NTIGuardrailMiddleware("agent_test")

        # Verify key was generated once in init
        assert mock_pqc_cls.generate.call_count == 1
        assert middleware.pqc_key is mock_pqc_key

        result = middleware.verify_tool_execution("test_tool", {"arg": "val"})

        assert result is True
        # Verify generate was not called again in verify_tool_execution
        assert mock_pqc_cls.generate.call_count == 1

        # Verify engine.evaluate was called with the exact canonical JSON string
        assert mock_engine.evaluate.call_count == 1
        evaluated_json_str = mock_engine.evaluate.call_args[0][0]

        # Verify signed message matches evaluated string
        assert mock_pqc_key.sign.call_count == 1
        signed_message = mock_pqc_key.sign.call_args[0][0].decode("utf-8")
        assert signed_message == evaluated_json_str

        # Parse evaluated string to check canonical fields
        parsed = json.loads(evaluated_json_str)
        assert parsed["actor"] == "agent_test"
        assert parsed["capability"] == "test_tool"
        assert parsed["input"] == {"arg": "val"}
        assert parsed["pqc_public_key"] is None


def test_tool_utils_interception_allowed():
    """Verify tool execution proceeds when guardrail allows."""
    mock_tool = CrewStructuredTool.from_function(
        func=lambda x: f"hello {x}", name="test_tool", description="test tool"
    )
    action = AgentAction(
        thought="thinking",
        tool="test_tool",
        tool_input='{"x": "world"}',
        text='Action: test_tool\nAction Input: {"x": "world"}',
    )

    mock_middleware = MagicMock()
    mock_middleware.verify_tool_execution.return_value = True

    with patch.object(
        __import__(
            "crewai.utilities.tool_utils", fromlist=["NTIGuardrailMiddleware"]
        ),
        "NTIGuardrailMiddleware",
        return_value=mock_middleware,
    ):
        result = execute_tool_and_check_finality(
            agent_action=action, tools=[mock_tool]
        )
        assert "hello world" in str(result.result)


def test_tool_utils_interception_denied():
    """Verify PermissionError is raised when guardrail denies tool execution."""
    mock_tool = CrewStructuredTool.from_function(
        func=lambda x: f"hello {x}", name="test_tool", description="test tool"
    )
    action = AgentAction(
        thought="thinking",
        tool="test_tool",
        tool_input='{"x": "world"}',
        text='Action: test_tool\nAction Input: {"x": "world"}',
    )

    mock_middleware = MagicMock()
    mock_middleware.verify_tool_execution.return_value = False

    with patch.object(
        __import__(
            "crewai.utilities.tool_utils", fromlist=["NTIGuardrailMiddleware"]
        ),
        "NTIGuardrailMiddleware",
        return_value=mock_middleware,
    ):
        with pytest.raises(
            PermissionError, match="NTI Security: Tool execution denied."
        ):
            execute_tool_and_check_finality(agent_action=action, tools=[mock_tool])


def test_is_public_ip():
    """Verify is_public_ip identifies public vs private/reserved/loopback/metadata IPs."""
    assert nti_module.is_public_ip("8.8.8.8") is True
    assert nti_module.is_public_ip("1.1.1.1") is True
    assert nti_module.is_public_ip("93.184.216.34") is True

    # Private, loopback, link-local, metadata
    assert nti_module.is_public_ip("127.0.0.1") is False
    assert nti_module.is_public_ip("10.0.0.1") is False
    assert nti_module.is_public_ip("172.16.0.1") is False
    assert nti_module.is_public_ip("192.168.1.1") is False
    assert nti_module.is_public_ip("169.254.169.254") is False
    assert nti_module.is_public_ip("0.0.0.0") is False
    assert nti_module.is_public_ip("::1") is False
    assert nti_module.is_public_ip("::ffff:127.0.0.1") is False
    assert nti_module.is_public_ip("::ffff:169.254.169.254") is False


def test_validate_url_valid():
    """Verify validate_url allows public URLs."""
    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        url = "https://example.com"
        assert nti_module.validate_url(url) == url


def test_validate_url_ssrf_blocked():
    """Verify validate_url blocks non-public IPs, bad schemes, and metadata URLs."""
    with pytest.raises(ValueError, match="forbidden"):
        nti_module.validate_url("http://127.0.0.1/admin")

    with pytest.raises(ValueError, match="forbidden"):
        nti_module.validate_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(ValueError, match="forbidden"):
        nti_module.validate_url("http://10.0.0.1/internal")

    with pytest.raises(ValueError, match="Invalid URL scheme"):
        nti_module.validate_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="Invalid URL scheme"):
        nti_module.validate_url("ftp://example.com/file")

    # Hostname resolving to private IP
    mock_private_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]
    with patch("socket.getaddrinfo", return_value=mock_private_addrinfo):
        with pytest.raises(ValueError, match="forbidden"):
            nti_module.validate_url("http://internal-host.local")


def test_socket_level_ip_pinning_prevents_dns_rebinding():
    """Verify create_pinned_socket enforces socket-level IP checks before and after connect."""
    # Pre-connect DNS rebinding attempt returning private IP
    mock_rebind_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
    with patch("socket.getaddrinfo", return_value=mock_rebind_addrinfo):
        with pytest.raises(ValueError, match="forbidden"):
            nti_module.create_pinned_socket("rebinding.host", 80)

    # Post-connect peer IP check failure
    mock_public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    mock_socket_obj = MagicMock()
    mock_socket_obj.getpeername.return_value = ("169.254.169.254", 80)

    with patch("socket.getaddrinfo", return_value=mock_public_addrinfo), patch(
        "socket.socket", return_value=mock_socket_obj
    ):
        with pytest.raises(ValueError, match="forbidden"):
            nti_module.create_pinned_socket("rebinding.host", 80)
        assert mock_socket_obj.close.called


def test_safe_request_redirect_revalidation():
    """Verify safe_request re-validates redirect locations and blocks SSRF redirect chains."""
    mock_addrinfo_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    redirect_response = MagicMock()
    redirect_response.status_code = 302
    redirect_response.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    mock_session = MagicMock()
    mock_session.request.return_value = redirect_response

    with patch("socket.getaddrinfo", return_value=mock_addrinfo_public), patch(
        "crewai.security.nti_guardrail.create_safe_session", return_value=mock_session
    ):
        with pytest.raises(ValueError, match="forbidden"):
            nti_module.safe_request("GET", "https://example.com")
