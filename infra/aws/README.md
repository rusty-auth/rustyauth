# AWS backup storage

`backup-bucket.yaml` provisions the production recovery boundary RustyAuth expects:

- S3 Versioning and 90-day compliance-mode Object Lock by default;
- bucket-default SSE-KMS with automatic customer-key rotation and an S3 Bucket Key;
- a separate KMS key whose decrypt policy is bound to the RustyAuth tenant and the `master`/`backup`
  application-key purposes;
- lifecycle expiry only after the immutable retention horizon;
- blocked public access and plaintext transport; and
- application access limited to `ListBucket`, `GetObject` and `PutObject`, with explicit denies for deletion
  and retention bypass.

The application principal is created separately so its access key can follow the deployment platform's
secret-delivery process. Deploy the stack with that role or user ARN:

```sh
aws cloudformation deploy \
  --stack-name rustyauth-backups \
  --template-file infra/aws/backup-bucket.yaml \
  --parameter-overrides \
    BackupBucketName=example-rustyauth-backups \
    BackupApplicationPrincipalArn=arn:aws:iam::123456789012:role/rustyauth \
    RustyAuthTenantId=payments
```

Set `AUTH_BACKUP_BUCKET`, `AUTH_BACKUP_REGION` and `AUTH_BACKUP_ENDPOINT` from the outputs. Set
`AUTH_BACKUP_SSE=aws:kms`, `AUTH_BACKUP_SSE_KMS_KEY_ID` to the exact `KmsKeyArn` output, and
`AUTH_BACKUP_RETENTION_DAYS` to the stack's `RetentionDays` value.

`KmsKeyArn` protects S3's storage layer. `ApplicationEnvelopeKmsKeyArn` can encrypt the raw 32-byte master and
portable backup keys supplied through RustyAuth's KMS ciphertext inputs; it does not replace those application
keys. The runtime principal receives context-bound decrypt access only. Generate and escrow the application
keys outside the hosting account, and keep every previous key until its final protected backup has expired and
a clean-room drill has succeeded.
