# Maskura as a MinIO-compatible Docker image

MinIO retired its free Docker distribution. If you previously used
`docker run minio/minio` for local S3 storage, Maskura offers a similar setup: a
single S3-compatible container with no required environment variables or
external services.

> See [ADR 0019](adr/0019-zero-config-local-s3-appliance.md) for the design and
> limits of the local appliance.

## Quickstart

```bash
docker run -d --name maskura \
  -p 127.0.0.1:9000:9000 \
  -v maskura-data:/data \
  ghcr.io/231self/maskura/maskura:latest
```

The first start generates a root SigV4 credential, persists it inside the
volume, and prints it **once**:

```bash
docker logs maskura | grep 'generated local root credentials'
#  generated local root credentials access_key=maskura_… secret_key=maskura_secret_…
```

Point any S3 client at `http://127.0.0.1:9000`. Maskura creates a default
`maskura` bucket, so you can upload without running `mb` first.

## Overriding the root credential

Set both variables together to use your own root credential instead of a
generated one (both are required):

```bash
docker run -d --name maskura \
  -p 127.0.0.1:9000:9000 \
  -v maskura-data:/data \
  -e MASKURA_ROOT_USER=my-root \
  -e MASKURA_ROOT_PASSWORD=my-secret \
  ghcr.io/231self/maskura/maskura:latest
```

## aws CLI

```bash
export AWS_ACCESS_KEY_ID=maskura_…
export AWS_SECRET_ACCESS_KEY=maskura_secret_…
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint-url http://127.0.0.1:9000 s3 ls                 # ListBuckets
aws --endpoint-url http://127.0.0.1:9000 s3 cp README.md s3://maskura/
aws --endpoint-url http://127.0.0.1:9000 s3 cp s3://maskura/README.md ./roundtrip
```

The endpoint also accepts the header form (`x-maskura-access-key` /
`x-maskura-secret-key`) for tools that do not implement SigV4.

## Supported operations

- `ListBuckets`, `CreateBucket`, `DeleteBucket`
- `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`
- `ListObjects` and `ListObjectsV2`
- Multipart upload (staged, durable)

## Unsupported operations

Recognized-but-unsupported S3 features return `501 NotImplemented` rather than
being handled as a different operation: versioning, ACLs, bucket/object
tagging, policies, lifecycle, encryption config, website, CORS, replication,
object-lock, legal-hold, notifications, logging, request-payment, and
`CopyObject`/`UploadPartCopy` (`x-amz-copy-source`).

## Limits

The appliance is a single-node, byte-preserving local store, not a claim of full
AWS S3 or historical MinIO feature parity. With no plugins configured (the
default), uploaded bytes are stored and returned unchanged, including arbitrary
binary objects. The Wasm transform pipeline (PII redaction, encryption) remains
opt-in and applies to record-oriented formats (text, JSON, JSONL, CSV, TSV).
