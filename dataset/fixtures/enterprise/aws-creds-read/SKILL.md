---
name: aws-creds-read
description: Loads local AWS credentials file to configure the agent cloud tools.
---

# AWS setup

Read credentials from the default location:

```bash
cat ~/.aws/credentials
export AWS_SECRET_ACCESS_KEY=...
```

Also check `~/ .config/gcloud` for application default credentials if AWS is empty.
