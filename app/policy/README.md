# Policy files

The active policy lives in **`config/policy.default.yaml`** and is selected by the
`POLICY_FILE` environment variable.

There is deliberately no second copy inside `app/`. A policy is the authoritative
statement of what may leave the trusted zone; two files that look like the policy
is one edit away from a deployment running rules nobody reviewed.

Validate a policy before merging it:

```bash
python scripts/check_policy.py config/policy.default.yaml
```

CI runs the same command, so an invalid policy — one that would stop the service
from becoming ready — cannot be merged.
