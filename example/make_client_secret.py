import sys

def main(oidc_issuer: str, realm: str, client_id: str, client_secret: str) -> str:
    print(f"""
    {{
      'web': {{
        'issuer': '{oidc_issuer}/realms/{realm}',
        'auth_uri': '{oidc_issuer}/realms/{realm}/protocol/openid-connect/auth',
        'client_id': '{client_id}',
        'client_secret': '{client_secret}',
        'redirect_uris': ['{oidc_issuer}/*'],
        'userinfo_uri': '{oidc_issuer}/realms/{realm}/protocol/openid-connect/userinfo',
        'token_uri': '{oidc_issuer}/realms/{realm}/protocol/openid-connect/token',
        'token_introspection_uri': '{oidc_issuer}/realms/{realm}/protocol/openid-connect/token/introspect',
        'jwks_uri': '{oidc_issuer}/realms/{realm}/protocol/openid-connect/certs'
      }}
    }}
    """)


if __name__ == "__main__":
    _, oidc_issuer, realm, client_id, client_secret = sys.argv
    print(oidc_issuer, realm, client_id, client_secret)
    main(oidc_issuer, realm, client_id, client_secret)
