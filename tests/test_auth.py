import pytest
from rdheadless.auth import FailureLimiter
from rdheadless.file_login import _accepted_filename, AUTH_ROOT, AUTH_SUBMIT


def test_limiter():
    clock=[0.0]
    limiter=FailureLimiter(2,10.0,clock=lambda:clock[0])
    assert limiter.allowed('client')
    limiter.report('client',False)
    assert limiter.allowed('client')
    limiter.report('client',False)
    assert not limiter.allowed('client')
    assert limiter.allowed('other')
    clock[0]=10
    assert limiter.allowed('client')


def test_auth_file_names_are_restricted_and_paths_fixed():
    for safe in ('alice', 'good-password', 'hello+world', 'some_name'):
        assert _accepted_filename(safe)
    for unsafe in ('', '.', '..', 'abc/', 'x\\y', 'bad:word', 'a\x00b', 'x'*201):
        assert not _accepted_filename(unsafe)
    assert AUTH_SUBMIT.startswith(AUTH_ROOT+'/')
