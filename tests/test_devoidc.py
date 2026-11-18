#!/usr/bin/env python
"""Checks a running DevOidc from the outside, the way its callers use it.

    uv run --with cryptography --with truststore tests/test_devoidc.py --config <the file DevOidc was started with>

It needs DevOidc running (default https://localhost:5443) and one of its --config files, from which
it takes the first client and the first user. It signs in, so DevOidc's console shows the sign-ins.
Nothing is written anywhere. Exit code 0 = every check passed.

truststore makes Python judge the certificate as Windows does, which is how the API and the browser
judge it: DevOidc serves the ASP.NET Core development certificate, trusted in the user's Windows
store, and Python's own list of authorities does not know it.

With the environment variable SSL_CERT_FILE set, the checks trust the certificate in that file and
no other, and truststore is not needed. tests/run_checks.sh uses that: it makes a certificate, starts
DevOidc with it and runs these checks, on a machine where no development certificate is trusted.
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if os.environ.get("SSL_CERT_FILE"):
    https = urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"]))
else:
    import truststore

    truststore.inject_into_ssl()
    https = urllib.request.HTTPSHandler()

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   [{detail}]" if detail and not ok else ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect, https)


def call(method, url, form=None, headers=None):
    """(status, headers, text). A redirect is returned, not followed."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def claims_of(jwt):
    return json.loads(b64d(jwt.split(".")[1]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--issuer", default="https://localhost:5443")
    ap.add_argument("--config", required=True, help="one of the files DevOidc was started with")
    a = ap.parse_args()
    iss = a.issuer.rstrip("/")
    with open(a.config, encoding="utf-8") as f:
        cfg = json.load(f)
    client = cfg["clients"][0]
    cid, redirect = client["client_id"], client["redirect_uris"][0]
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(redirect))
    email = cfg["users"][0]["email"]
    lifetime = client.get("token_lifetime_seconds", 3600)

    def grant(**extra):
        s, _h, body = call("POST", f"{iss}/token", {"grant_type": "urn:devoidc:user", "client_id": cid, **extra})
        return s, json.loads(body)

    print("Discovery and keys")
    s, _h, body = call("GET", f"{iss}/.well-known/openid-configuration")
    meta = json.loads(body) if s == 200 else {}
    check("discovery answers and names this issuer, with no slash at the end", s == 200 and meta.get("issuer") == iss, body[:120])
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"):
        check(f"discovery has {key}", str(meta.get(key, "")).startswith(iss + "/"))
    s, _h, body = call("GET", meta.get("jwks_uri", f"{iss}/jwks"))
    keys = json.loads(body).get("keys", []) if s == 200 else []
    check("one RSA signing key is published", len(keys) == 1 and keys[0].get("kty") == "RSA" and keys[0].get("alg") == "RS256")
    public = rsa.RSAPublicNumbers(int.from_bytes(b64d(keys[0]["e"]), "big"), int.from_bytes(b64d(keys[0]["n"]), "big")).public_key()

    def signed_by_devoidc(jwt):
        head, payload, sig = jwt.split(".")
        try:
            public.verify(b64d(sig), f"{head}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
            return json.loads(b64d(head)).get("kid") == keys[0]["kid"]
        except Exception:
            return False

    print("The script grant (a token without the page)")
    s, t = grant(email=email)
    c = claims_of(t["id_token"]) if s == 200 else {}
    now = int(time.time())
    check("a token comes back, signed with the published key", s == 200 and signed_by_devoidc(t["id_token"]), str(t)[:120])
    check("iss is the issuer and aud is the client", c.get("iss") == iss and c.get("aud") == cid)
    check("email, emails, name, given_name and family_name are there", c.get("email") == email and c.get("emails") == [email] and all(k in c for k in ("name", "given_name", "family_name")))
    check("auth_time, iat and exp are whole seconds, now", isinstance(c.get("auth_time"), int) and abs(c["auth_time"] - now) <= 5 and abs(c.get("iat", 0) - now) <= 5)
    check("the lifetime is the client's", c.get("exp", 0) - c.get("iat", 0) == lifetime)
    check("the access token is the same signed token", t.get("access_token") == t.get("id_token"))
    s, t2 = grant(email=email.upper())
    c2 = claims_of(t2["id_token"])
    check("the same person gets the same sub, whatever the case of the e-mail", c2.get("sub") == c.get("sub"))
    check("two sign-ins in a row never share an auth_time", c2.get("auth_time", 0) > c.get("auth_time", 0), f"{c.get('auth_time')} then {c2.get('auth_time')}")
    s, t3 = grant(email="someone.else@example.test")
    c3 = claims_of(t3["id_token"])
    check("an e-mail that is not listed still signs in, with a name made from the address", s == 200 and c3.get("name") == "Someone Else" and c3.get("sub") != c.get("sub"))

    print("The script grant's switches for tests of refusal")
    s, t = grant(email=email, lifetime_seconds="-600")
    c = claims_of(t["id_token"])
    check("lifetime_seconds=-600 gives a token that expired ten minutes ago", s == 200 and c["exp"] <= int(time.time()) - 595 and c["iat"] < c["exp"])
    s, t = grant(email=email, auth_time="1700000000")
    check("auth_time is taken as given", s == 200 and claims_of(t["id_token"])["auth_time"] == 1700000000)
    s, t = grant(email=email, aud="another-audience")
    check("aud is taken as given", s == 200 and claims_of(t["id_token"])["aud"] == "another-audience")
    s, t = grant()
    check("no e-mail is refused", s == 400 and t.get("error") == "invalid_request")
    s, _h, body = call("POST", f"{iss}/token", {"grant_type": "urn:devoidc:user", "client_id": "not-registered", "email": email})
    check("an unknown client is refused", s == 400 and json.loads(body).get("error") == "invalid_client")
    s, _h, body = call("POST", f"{iss}/token", {"grant_type": "password", "client_id": cid})
    check("another grant type is refused", s == 400 and json.loads(body).get("error") == "unsupported_grant_type")

    print("Sign-in through the page (authorization code with PKCE)")
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    ask = {"client_id": cid, "redirect_uri": redirect, "response_type": "code", "response_mode": "fragment", "scope": "openid profile offline_access",
           "state": "state-123", "nonce": "nonce-456", "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login"}
    s, _h, page = call("GET", f"{iss}/authorize?" + urllib.parse.urlencode(ask))
    check("the page lists the users and asks no password", s == 200 and email in page and 'type="password"' not in page)

    def sign_in(**changes):
        s, h, _b = call("POST", f"{iss}/authorize", {**ask, "email": email, **changes})
        where = h.get("Location", "")
        sep = "#" if "#" in where else "?"
        return s, where, dict(urllib.parse.parse_qsl(where.split(sep, 1)[1])) if sep in where else {}

    s, where, back = sign_in()
    check("choosing a user returns to the redirect address, in the fragment, with the state", s == 302 and where.startswith(redirect + "#") and back.get("state") == "state-123" and "code" in back, where[:100])
    redeem = {"grant_type": "authorization_code", "client_id": cid, "redirect_uri": redirect, "code_verifier": verifier, "client_info": "1"}
    s, _h, body = call("POST", f"{iss}/token", {**redeem, "code": back.get("code", "")})
    t = json.loads(body)
    c = claims_of(t["id_token"]) if s == 200 else {}
    check("the code buys an ID token carrying the nonce, and a refresh token", s == 200 and signed_by_devoidc(t["id_token"]) and c.get("nonce") == "nonce-456" and "refresh_token" in t, body[:160])
    check("an access token is issued only when the client asks for one", ("access_token" in t) == client.get("access_token", True))
    info = json.loads(b64d(t.get("client_info", "e30"))) if s == 200 else {}
    check("client_info=1 is answered, for Microsoft's libraries", info.get("uid") == c.get("sub") and bool(info.get("utid")))
    s, _h, body = call("POST", f"{iss}/token", {**redeem, "code": back.get("code", "")})
    check("a code works once", s == 400 and json.loads(body).get("error") == "invalid_grant")
    _s, _w, back2 = sign_in()
    s, _h, body = call("POST", f"{iss}/token", {**redeem, "code": back2.get("code", ""), "code_verifier": "wrong-" + verifier})
    check("the wrong code_verifier is refused", s == 400 and json.loads(body).get("error") == "invalid_grant")
    s, where, back3 = sign_in(response_mode="query")
    check("response_mode=query answers in the query", s == 302 and where.startswith(redirect + "?") and "code" in back3)

    s, _h, body = call("POST", f"{iss}/token", {"grant_type": "refresh_token", "client_id": cid, "refresh_token": t.get("refresh_token", "")})
    r = json.loads(body)
    rc = claims_of(r["id_token"]) if s == 200 else {}
    check("the refresh token renews, keeping the moment of the sign-in and dropping the nonce", s == 200 and rc.get("auth_time") == c.get("auth_time") and "nonce" not in rc and rc.get("sub") == c.get("sub"), body[:160])

    print("What the sign-in page refuses")
    s, h, body = call("GET", f"{iss}/authorize?" + urllib.parse.urlencode({**ask, "redirect_uri": "https://elsewhere.example/callback"}))
    check("an unregistered redirect address gets a page, never a redirect", s == 400 and "Location" not in h and "not registered" in body)
    s, h, _b = call("GET", f"{iss}/authorize?" + urllib.parse.urlencode({**ask, "prompt": "none"}))
    check("prompt=none answers login_required", s == 302 and "error=login_required" in h.get("Location", ""))
    no_pkce = {k: v for k, v in ask.items() if not k.startswith("code_challenge")}
    s, h, _b = call("GET", f"{iss}/authorize?" + urllib.parse.urlencode(no_pkce))
    check("a request without PKCE is refused", s == 302 and "error=invalid_request" in h.get("Location", ""))

    print("userinfo, sign-out and the browser's cross-origin calls")
    s, _h, body = call("GET", f"{iss}/userinfo", headers={"Authorization": "Bearer " + t["id_token"]})
    check("userinfo answers a token with its person", s == 200 and json.loads(body).get("email") == email)
    s, _h, _b = call("GET", f"{iss}/userinfo")
    check("userinfo without a token is 401", s == 401)
    after = client["post_logout_redirect_uris"][0]
    s, h, _b = call("GET", f"{iss}/logout?" + urllib.parse.urlencode({"id_token_hint": t["id_token"], "post_logout_redirect_uri": after + "?reason=inactivity", "state": "bye"}))
    check("sign-out returns to the registered address, keeping its query and the state", s == 302 and h.get("Location", "") == after + "?reason=inactivity&state=bye", h.get("Location", ""))
    s, _h, body = call("POST", f"{iss}/token", {"grant_type": "refresh_token", "client_id": cid, "refresh_token": t.get("refresh_token", "")})
    check("after the sign-out the refresh token no longer renews", s == 400 and json.loads(body).get("error") == "invalid_grant")
    s, h, body = call("GET", f"{iss}/logout?" + urllib.parse.urlencode({"post_logout_redirect_uri": "https://elsewhere.example/"}))
    check("sign-out to an unregistered address gets a page, never a redirect", s == 400 and "Location" not in h)
    s, h, _b = call("OPTIONS", f"{iss}/token", headers={"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    check("the application's origin may call /token from the browser", s == 204 and h.get("Access-Control-Allow-Origin") == origin)
    s, h, _b = call("GET", f"{iss}/.well-known/openid-configuration", headers={"Origin": "https://elsewhere.example"})
    check("another origin gets no cross-origin permission", h.get("Access-Control-Allow-Origin") is None)

    failed = results.count(False)
    print(f"\n{len(results)} checks, {failed} failed" if failed else f"\n{len(results)} checks, all passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
