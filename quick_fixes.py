import ssl
import requests

ctx = ssl.create_default_context()
print(ctx.protocol)  # Expected: 3 (TLS 1.2) or 4 (TLS 1.3)

response = requests.get("https://production.plaid.com/", verify=True)
print(response.raw.version)  # Expected: 3 (TLS 1.2) or 4 (TLS 1.3)
