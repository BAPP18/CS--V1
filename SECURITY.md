# Security Policy

## Intended use

CS--V1 is an educational and defensive cybersecurity toolkit.

Use network scanning and packet capture only on systems, interfaces, and networks that you own or are explicitly authorized to test.

## Reporting a security issue in this project

Please avoid publishing sensitive exploit details in a public issue if the issue could affect users of this repository. Contact the repository owner privately where possible.

## Secrets

Do not commit:
- API keys
- tokens
- passwords
- private keys
- packet captures containing sensitive traffic
- production logs containing credentials or personal data

Use environment variables for secrets such as `NVD_API_KEY`.
