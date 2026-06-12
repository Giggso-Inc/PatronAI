# PatronAI — OCI Migration Guide

This branch contains the full OCI deployment of PatronAI.
All source environment scripts (AWS) are removed. This is a clean OCI-only branch.

---

## New Files vs Original

| File | Purpose |
|------|---------|
| `deploy_to_oci.sh` | Deploy codebase from Mac → OCI VM |
| `prereqs_oci.sh` | Create OCI resources + generate .env |
| `oci-policy.json` | OCI IAM policy for PatronAI |
| `ghost-ai-scanner/scripts/migrate_data.sh` | Migrate data from source environment → OCI |

---

## Modified Files

| File | What changed |
|------|-------------|
| `ghost-ai-scanner/docker-compose.yml` | Added `S3_ENDPOINT_URL`, `CLOUD_PROVIDER=oci` |
| `ghost-ai-scanner/nginx/nginx.conf` | Fixed routing, HTTP→HTTPS, websocket block |
| `ghost-ai-scanner/scripts/setup.sh` | OCI Object Storage validation instead of AWS CLI |
| `ghost-ai-scanner/scripts/start.sh` | OCI S3-compat check instead of AWS STS check |
| `ghost-ai-scanner/.env.example` | OCI credentials, `S3_ENDPOINT_URL`, `us-chicago-1` |
| `README.md` | Full OCI rewrite |

---

## Migration Flow

```
STEP 1  bash deploy_to_oci.sh
         Copies codebase from Mac → OCI VM
         Installs Docker if needed
         Sets up MCP server + LLM

STEP 2  bash prereqs_oci.sh
         Creates OCI Object Storage bucket
         Generates Customer Secret Keys
         Creates OCI Notifications topic
         Generates .env with OCI values
         SCPs .env → OCI VM

STEP 3  bash ghost-ai-scanner/scripts/migrate_data.sh
         Syncs source S3 bucket → OCI Object Storage via rclone
         Migrates grafana-data Docker volume
         LLM model volume skipped (auto re-downloads)

STEP 4  SSH into OCI VM
         cd ghost-ai-scanner
         bash scripts/start.sh

STEP 5  Verify healthy
         docker ps -a
         curl -k https://<OCI_IP>/
         curl -k https://<OCI_IP>/grafana/

STEP 6  Switch DNS
         patronai.giggso.com A → <OCI_IP>

STEP 7  Monitor 24-48 hours → terminate source environment
```

---

## OCI Service Mapping

| Source (AWS) | OCI | Variable |
|-------------|-----|---------|
| EC2 | OCI Compute VM | — |
| S3 | OCI Object Storage (S3-compat) | `PATRONAI_BUCKET` + `S3_ENDPOINT_URL` |
| IAM user + keys | Customer Secret Keys | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (boto3 names) |
| SNS | OCI Notifications (ONS) | `ALERT_SNS_ARN` (stores ONS topic OCID) |
| SES | OCI Email Delivery | `PATRONAI_FROM_EMAIL` |
| VPC Flow Logs | VCN Flow Logs | — |

> **Note on variable names:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
> and `AWS_REGION` are boto3 (Python S3 SDK) required variable names.
> They store OCI credentials — not AWS credentials.

---

## OCI Region

```
Region : us-chicago-1
City   : Chicago, Illinois, USA
```

---

## Developer Backlog (source code changes needed)

| Feature | File | Status |
|---------|------|--------|
| OCI VNIC network resolver | `src/identity_resolver/source_ec2.py` | In progress |
| OCI ONS alert dispatcher | `src/alerter/dispatcher.py` | In progress |
| OCI Email Delivery | `src/notify/email.py` | In progress |
| VCN Flow Log normaliser | `src/normalizer/flow_log.py` | Planned |

---

*Giggso Inc x TrinityOps.ai x AIRTaaS*
