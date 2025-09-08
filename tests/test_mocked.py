#!/usr/bin/env python
"""Tests for httpx_gssapi."""

import logging
from base64 import b64encode
from unittest.mock import Mock, patch

import pytest

import httpx

import gssapi
import gssapi.exceptions

import httpx_gssapi
from httpx_gssapi import REQUIRED, OPTIONAL

logging.basicConfig()

fake_init = Mock(return_value=None)
fake_creds = Mock(return_value=b"fake creds")
fake_resp = Mock(return_value=b"GSSRESPONSE")

# GSSAPI exceptions require a major and minor status code for their
# construction, so construct a *really* fake one
fail_resp = Mock(side_effect=gssapi.exceptions.GSSError(0, 0))

gssflags = [gssapi.RequirementFlag.out_of_sequence_detection]
mutflags = gssflags + [gssapi.RequirementFlag.mutual_authentication]
gssdelegflags = gssflags + [gssapi.RequirementFlag.delegate_to_peer]

# The base64 behavior we want is that encoding produces a string, but decoding
# produces bytes.  Remember, GSSAPI tokens are opaque here.
b64_negotiate_response = "Negotiate " + b64encode(b"GSSRESPONSE").decode()
b64_negotiate_token = "negotiate " + b64encode(b"token").decode()
b64_negotiate_server = "negotiate " + b64encode(b"servertoken").decode()

neg_response = {'www-authenticate': b64_negotiate_response}
neg_token = {'www-authenticate': b64_negotiate_token}
neg_server = {'www-authenticate': b64_negotiate_server}


@pytest.fixture
def patched_creds():
    fake_creds.reset_mock()
    with patch.multiple("gssapi.Credentials", __new__=fake_creds):
        yield


@pytest.fixture
def patched_ctx():
    fake_init.reset_mock()
    fake_resp.reset_mock()
    with patch.multiple("gssapi.SecurityContext",
                        __init__=fake_init,
                        step=fake_resp):
        yield


@pytest.fixture
def patched_ctx_fail():
    fake_init.reset_mock()
    fail_resp.reset_mock()
    with patch.multiple("gssapi.SecurityContext",
                        __init__=fake_init,
                        step=fail_resp):
        yield


def gssapi_name(s):
    return gssapi.Name(s, gssapi.NameType.hostbased_service)


def null_request(method='GET', url="http://www.example.org/", **kwargs):
    return httpx.Request(method, url, **kwargs)


def null_response(status=200, request=null_request(), **kwargs):
    return httpx.Response(status, request=request, **kwargs)


def check_init(**kwargs):
    kwargs.setdefault('name', gssapi_name("HTTP@www.example.org"))
    kwargs.setdefault('creds', None)
    kwargs.setdefault('mech', gssapi.OID.from_int_seq("1.3.6.1.5.5.2"))
    kwargs.setdefault('flags', gssflags)
    kwargs.setdefault('usage', "initiate")
    fake_init.assert_called_with(**kwargs)


def test_negotate_value_extraction():
    response = null_response(headers=neg_token)
    assert httpx_gssapi.gssapi_._negotiate_value(response) == b'token'


def test_negotate_value_extraction_none():
    response = null_response(headers={})
    assert httpx_gssapi.gssapi_._negotiate_value(response) is None


def test_force_preemptive(patched_ctx):
    auth = httpx_gssapi.HTTPSPNEGOAuth(opportunistic_auth=True)

    request = null_request()

    flow = auth.auth_flow(request)
    next(flow)  # Move to first request yield

    assert 'Authorization' in request.headers
    assert request.headers.get('Authorization') == b64_negotiate_response


def test_no_force_preemptive(patched_ctx):
    auth = httpx_gssapi.HTTPSPNEGOAuth()

    request = null_request()

    flow = auth.auth_flow(request)
    next(flow)  # Move to first request yield

    assert 'Authorization' not in request.headers


def test_generate_request_header(patched_ctx):
    resp = null_response(headers=neg_token)
    auth = httpx_gssapi.HTTPSPNEGOAuth()
    auth.set_auth_header(resp.request, resp)
    assert resp.request.headers['Authorization'] == b64_negotiate_response
    check_init()
    fake_resp.assert_called_with(b"token")


def test_generate_request_header_init_error(patched_ctx_fail):
    response = null_response(headers=neg_token)
    auth = httpx_gssapi.HTTPSPNEGOAuth()
    with pytest.raises(httpx_gssapi.exceptions.SPNEGOExchangeError):
        auth.set_auth_header(response.request, response)
    check_init()


def test_generate_request_header_step_error(patched_ctx_fail):
    response = null_response(headers=neg_token)
    auth = httpx_gssapi.HTTPSPNEGOAuth()
    with pytest.raises(httpx_gssapi.exceptions.SPNEGOExchangeError):
        auth.set_auth_header(response.request, response)
    check_init()
    fail_resp.assert_called_with(b"token")


def test_authenticate_server(patched_ctx):
    response_ok = null_response(headers={
        'www-authenticate': b64_negotiate_server,
        'authorization': b64_negotiate_response,
    })

    auth = httpx_gssapi.HTTPSPNEGOAuth()
    assert auth.authenticate_server(response_ok, gssapi.SecurityContext())
    fake_resp.assert_called_with(b"servertoken")


def test_handle_mutual_auth(patched_ctx):
    response_ok = null_response(headers={
        'www-authenticate': b64_negotiate_server,
        'authorization': b64_negotiate_response,
    })

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=REQUIRED)

    # No error raised
    auth.handle_mutual_auth(response_ok, gssapi.SecurityContext())
    fake_resp.assert_called_with(b"servertoken")


def test_handle_response_200(patched_ctx):
    response_ok = null_response(headers={
        'www-authenticate': b64_negotiate_server,
        'authorization': b64_negotiate_response,
    })

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=REQUIRED)

    flow = auth.handle_response(response_ok, gssapi.SecurityContext())
    with pytest.raises(StopIteration):  # No other requests required
        next(flow)
    fake_resp.assert_called_with(b"servertoken")


def test_handle_response_200_mutual_auth_required_failure(patched_ctx_fail):
    response_ok = null_response()

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=REQUIRED)

    flow = auth.handle_response(response_ok, gssapi.SecurityContext())
    with pytest.raises(httpx_gssapi.MutualAuthenticationError):
        next(flow)

    assert not fail_resp.called


def test_handle_response_200_mutual_auth_required_failure_2(patched_ctx_fail):
    response_ok = null_response(headers={
        'www-authenticate': b64_negotiate_server,
        'authorization': b64_negotiate_response,
    })

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=REQUIRED)

    flow = auth.handle_response(response_ok, gssapi.SecurityContext())
    with pytest.raises(httpx_gssapi.MutualAuthenticationError):
        next(flow)

    fail_resp.assert_called_with(b"servertoken")


def test_handle_response_200_mutual_auth_optional_hard_fail(patched_ctx_fail):
    response_ok = null_response(headers={
        'www-authenticate': b64_negotiate_server,
        'authorization': b64_negotiate_response,
    })

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=OPTIONAL)

    flow = auth.handle_response(response_ok, gssapi.SecurityContext())
    with pytest.raises(httpx_gssapi.MutualAuthenticationError):
        next(flow)

    fail_resp.assert_called_with(b"servertoken")


def test_handle_response_200_mutual_auth_optional_soft_failure(patched_ctx):
    response_ok = null_response()

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=OPTIONAL)
    auth.context = {"www.example.org": gssapi.SecurityContext}

    flow = auth.handle_response(response_ok)
    with pytest.raises(StopIteration):  # advance flow with no new requests
        next(flow)

    assert not fake_resp.called


def test_handle_response_500_mutual_auth_required_failure(patched_ctx_fail):
    response_500 = null_response(
        status=500,
        headers={'date': 'DATE', 'content-length': '100', 'other': 'x'},
    )
    response_500._content = b"CONTENT"

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=REQUIRED)

    flow = auth.handle_response(response_500, gssapi.SecurityContext())
    with pytest.raises(StopIteration):  # advance flow with no new requests
        next(flow)

    assert 'other' not in response_500.headers
    assert response_500.headers['date'] == 'DATE'
    assert response_500.headers['content-length'] == '0'
    assert response_500.content == b''

    assert not fail_resp.called


def test_handle_response_500_mutual_auth_required_fail_no_san(patched_ctx_fail):
    response_500 = null_response(
        status=500,
        headers={'date': 'DATE', 'content-length': '100', 'other': 'x'},
    )
    response_500._content = b'CONTENT'

    auth = httpx_gssapi.HTTPSPNEGOAuth(
        mutual_authentication=REQUIRED,
        sanitize_mutual_error_response=False
    )
    auth.context = {"www.example.org": "CTX"}

    flow = auth.handle_response(response_500)
    with pytest.raises(StopIteration):  # advance flow with no new requests
        next(flow)

    assert response_500.headers['other'] == 'x'
    assert response_500.headers['date'] == 'DATE'
    assert response_500.headers['content-length'] == '100'
    assert response_500.content == b'CONTENT'

    assert not fail_resp.called


def test_handle_response_500_mutual_auth_optional_failure(patched_ctx_fail):
    response_500 = null_response(
        status=500,
        headers={'date': 'DATE', 'content-length': '100', 'other': 'x'},
    )
    response_500._content = b'CONTENT'

    auth = httpx_gssapi.HTTPSPNEGOAuth(mutual_authentication=OPTIONAL)
    auth.context = {"www.example.org": "CTX"}

    flow = auth.handle_response(response_500)
    with pytest.raises(StopIteration):  # advance flow with no new requests
        next(flow)

    assert response_500.headers['other'] == 'x'
    assert response_500.headers['date'] == 'DATE'
    assert response_500.headers['content-length'] == '100'
    assert response_500.content == b'CONTENT'

    assert not fail_resp.called


def test_handle_response_401(patched_ctx):
    auth = httpx_gssapi.HTTPSPNEGOAuth()
    response_401 = null_response(status=401, headers=neg_token)
    flow = auth.handle_response(response_401)
    request = next(flow)
    assert isinstance(request, httpx.Request)
    assert request.headers['Authorization'] == b64_negotiate_response
    response_ok = null_response(headers=neg_server, request=request)
    with pytest.raises(StopIteration):  # no more requests
        flow.send(response_ok)
    check_init()
    fake_resp.assert_called_with(b"token")


def test_handle_response_401_rejected(patched_ctx):
    # Get a 401 from server, authenticate, and get another 401 back.
    # Ensure there is no infinite auth loop.
    auth = httpx_gssapi.HTTPSPNEGOAuth()
    response_401 = null_response(status=401, headers=neg_token)
    flow = auth.handle_response(response_401)

    request = next(flow)
    assert isinstance(request, httpx.Request)
    assert request.headers['Authorization'] == b64_negotiate_response

    response_401 = null_response(status=401, headers=neg_token, request=request)
    request = flow.send(response_401)
    assert isinstance(request, httpx.Request)
    assert request.headers['Authorization'] == b64_negotiate_response

    with pytest.raises(StopIteration):  # no more requests, max is 2
        flow.send(null_response(status=401, headers=neg_token, request=request))
    check_init()
    fake_resp.assert_called_with(b"token")


def test_delegation(patched_ctx):
    auth = httpx_gssapi.HTTPSPNEGOAuth(delegate=True)
    response_401 = null_response(status=401, headers=neg_token)
    flow = auth.handle_response(response_401)
    request = next(flow)
    assert isinstance(request, httpx.Request)
    assert request.headers['Authorization'] == b64_negotiate_response
    response_ok = null_response(headers=neg_server, request=request)
    with pytest.raises(StopIteration):  # no more requests
        flow.send(response_ok)
    check_init(flags=gssdelegflags)
    fake_resp.assert_called_with(b"token")


def test_opportunistic_auth(patched_ctx):
    auth = httpx_gssapi.HTTPSPNEGOAuth(opportunistic_auth=True)

    request = null_request()

    flow = auth.auth_flow(request)
    assert next(flow) is request

    assert 'Authorization' in request.headers
    assert request.headers.get('Authorization') == b64_negotiate_response


def test_explicit_creds(patched_creds, patched_ctx):
    response = null_response(headers=neg_token)
    creds = gssapi.Credentials()
    auth = httpx_gssapi.HTTPSPNEGOAuth(creds=creds)
    auth.set_auth_header(response.request, response)
    check_init(creds=b"fake creds")
    fake_resp.assert_called_with(b"token")


def test_explicit_mech(patched_creds, patched_ctx):
    response = null_response(headers=neg_token)
    fake_mech = b'fake mech'
    auth = httpx_gssapi.HTTPSPNEGOAuth(mech=fake_mech)
    auth.set_auth_header(response.request, response)
    check_init(mech=b'fake mech')
    fake_resp.assert_called_with(b"token")


def test_target_name(patched_ctx):
    response = null_response(headers=neg_token)
    target = "HTTP@otherhost.otherdomain.org"
    auth = httpx_gssapi.HTTPSPNEGOAuth(target_name=target)
    auth.set_auth_header(response.request, response)
    check_init(name=gssapi_name(target))
    fake_resp.assert_called_with(b"token")


def test_os_default_mech(patched_ctx):
    resp = null_response(headers=neg_token)
    auth = httpx_gssapi.HTTPSPNEGOAuth(mech=None)
    auth.set_auth_header(resp.request, resp)
    assert resp.request.headers['Authorization'] == b64_negotiate_response
    check_init(mech=None)
    fake_resp.assert_called_with(b"token")


if __name__ == '__main__':
    pytest.main()
