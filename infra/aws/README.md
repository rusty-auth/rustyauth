# AWS backup storage

`backup-bucket.yaml` provisions the production recovery boundary RustyAuth expects:

- S3 Versioning and 90-day compliance-mode Object Lock by default;
- bucket-default SSE-KMS with automatic customer-key rotation and an S3 Bucket Key;
- lifecycle expiry only after the immutable retention horizon;
- blocked public access and plaintext transport; and
- application access limited to `ListBucket`, `GetObject` and `PutObject`, with explicit denies for deletion and retention bypass.

The application principal is created separately so its access key can follow the deployment platform's secret-delivery process. Deploy the stack with that role or user ARN:

```sh
aws cloudformation deploy \
  --stack-name rustyauth-backups \
  --template-file infra/aws/backup-bucket.yaml \
  --parameter-overrides \
    BackupBucketName=example-rustyauth-backups \
    BackupApplicationPrincipalArn=arn:aws:iam::123456789012:role/rustyauth
```

Set `AUTH_BACKUP_BUCKET`, `AUTH_BACKUP_REGION` and `AUTH_BACKUP_ENDPOINT` from the outputs. Set `AUTH_BACKUP_SSE=aws:kms`, `AUTH_BACKUP_SSE_KMS_KEY_ID` to the exact `KmsKeyArn` output, and `AUTH_BACKUP_RETENTION_DAYS` to the stack's `RetentionDays` value.

The KMS key protects S3's storage layer. It does **not** replace `AUTH_BACKUP_ENCRYPTION_KEY_HEX`, which encrypts the portable `.rauth` envelope before upload. Generate and escrow that application key outside both the application hosting account and this AWS account. Keep every previous application key until its final protected backup has expired and a clean-room drill has succeeded.
