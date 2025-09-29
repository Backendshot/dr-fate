1. Implementation of Tower services:
a. CORS
b. Compression (zstd with gzip as backup)
c. Rate limiting
d. Authentication (especially JWT, Bearer, OAuth, and API Key/Basic Authentication)
d1. Usage of argon2id (as specifically recommended by OWASP)
e. Session
f. Tracing (already added)
g. Metrics (OpenTelemetry and Tracing)
h. Retry
i. Timeout
2. Documentation
a. Docs
b. Swagger/OpenAPI
3. Testing
a. Unit Testing
b. Integration Testing
4. Miscellaneous
a. Audit Logs
- Website Audit (what browser was used)
- Operation Audit (what operation was performed, who changed what, and what changed)