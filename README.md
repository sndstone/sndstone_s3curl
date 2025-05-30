# s3curl.py

A Python implementation of s3curl with AWS Signature Version 4 support for secure S3 operations.

## Overview

`s3curl.py` is a command-line tool that provides curl-like functionality for Amazon S3, with full support for AWS Signature Version 4 authentication. This tool is essential for working with newer AWS regions that require SigV4, and provides a secure way to perform S3 operations from the command line.

## Features

- ✅ **AWS Signature Version 4** authentication (required for newer AWS regions)
- ✅ **Multiple HTTP methods**: GET, PUT, HEAD, DELETE, POST
- ✅ **Bucket operations**: Create buckets with region constraints
- ✅ **Object operations**: Upload, download, copy, and delete objects
- ✅ **Bucket sub-resources**: Access ACL, versioning, lifecycle, object-lock, and more
- ✅ **ACL support**: Set canned ACLs during uploads
- ✅ **Content MD5**: Manual or automatic calculation
- ✅ **Debug capabilities**: Save raw requests/responses for troubleshooting
- ✅ **Secure credential management**: Uses protected credential files
- ✅ **Region auto-detection**: Automatically detects region from bucket hostname

## Prerequisites

- **Python 3.x** (check with `python3 --version`)
- **requests library**: Install with `pip install requests`

## Installation

1. Download the script:
```bash
wget https://github.com/sndstone/sndstone_s3curl/main/s3curl.py
# or
curl -O https://github.com/sndstone/sndstone_s3curl/main/s3curl.py
```

2. Make it executable:
```bash
chmod +x s3curl.py
```

## Configuration

### Setting up AWS Credentials

Create a `.s3curl` file in your home directory with your AWS credentials:

```bash
# ~/.s3curl
awsSecretAccessKeys = {
    'personal': {
        'id': 'YOUR_ACCESS_KEY_ID',
        'key': 'YOUR_SECRET_ACCESS_KEY',
    },
    'company': {
        'id': 'ANOTHER_ACCESS_KEY_ID',
        'key': 'ANOTHER_SECRET_ACCESS_KEY',
    },
}
```

**Important**: Secure the credentials file:
```bash
chmod 600 ~/.s3curl
```

> ⚠️ **Security Note**: Never pass credentials via `--key` on the command line in production. The script will warn you and pause for 5 seconds if you do this.

## Usage

### Basic Syntax

```bash
./s3curl.py \
  --id <credential-profile-name> \
  [options] \
  -- \
  https://bucket.s3.region.amazonaws.com/object-key
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--id <profile>` | Credential profile name from `.s3curl` file |
| `--region <region>` | Override region detection |
| `--head` | Perform HEAD request |
| `--delete` | Perform DELETE request |
| `--put <file>` | Upload file with PUT request |
| `--post [<file>]` | Perform POST request (optionally with file) |
| `--createBucket [region]` | Create bucket (optionally in specific region) |
| `--copySrc "bucket/key"` | Copy source for object copying |
| `--copySrcRange <range>` | Byte range for partial copy (e.g., "0-999") |
| `--acl <canned-acl>` | Set canned ACL (e.g., "public-read") |
| `--contentType <mime>` | Set Content-Type header |
| `--contentMd5 <value>` | Set Content-MD5 header manually |
| `--calculateContentMd5` | Auto-calculate Content-MD5 from file |
| `--saveRequest <file>` | Save raw request/response to debug file |
| `--debug` | Enable verbose debug logging |

## Examples

### Basic Object Operations

#### Download an Object (GET)

```bash
# Download to stdout
./s3curl.py --id personal -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/myfile.txt

# Download to file
./s3curl.py --id personal -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/myfile.txt \
  > downloaded-file.txt

# Download specific version
./s3curl.py --id personal -- \
  "https://my-bucket.s3.eu-north-1.amazonaws.com/myfile.txt?versionId=abc123"

# Download partial content
./s3curl.py --id personal -- \
  -H "Range: bytes=0-999" \
  https://my-bucket.s3.eu-north-1.amazonaws.com/myfile.txt
```

#### Upload a File (PUT)

```bash
# Basic upload
./s3curl.py \
  --id personal \
  --put local-file.txt \
  --contentType text/plain \
  -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/remote-file.txt

# Upload with public-read ACL
./s3curl.py \
  --id personal \
  --put public-file.txt \
  --acl public-read \
  -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/public-file.txt
```

#### Check Object Metadata (HEAD)

```bash
./s3curl.py \
  --id personal \
  --head \
  -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/myfile.txt
```

#### Delete an Object

```bash
./s3curl.py \
  --id personal \
  --delete \
  -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/file-to-delete.txt
```

#### Copy an Object

```bash
./s3curl.py \
  --id personal \
  --copySrc "source-bucket/source-key" \
  -- \
  https://dest-bucket.s3.eu-north-1.amazonaws.com/dest-key
```

### Bucket Operations

#### Create a Bucket

```bash
# Create bucket in specific region
./s3curl.py \
  --id personal \
  --createBucket eu-north-1 \
  -- \
  https://my-new-bucket.s3.eu-north-1.amazonaws.com/
```

## Advanced S3 Operations

### Bucket Sub-Resources

All bucket-level sub-resource operations follow this general format:

```bash
./s3curl.py \
  --id <profileName> \
  -- \
  "https://<bucketName>.s3.<region>.amazonaws.com/?<sub-resource>"
```

The script defaults to GET unless you specify `--put`, `--post`, or `--delete`.

### Common Bucket Sub-Resources

| Sub-resource | Description | Example Command |
|--------------|-------------|-----------------|
| `?acl` | Get/Set bucket ACL | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?acl"` |
| `?versioning` | Get/Set versioning config | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?versioning"` |
| `?lifecycle` | Get/Set lifecycle policy | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?lifecycle"` |
| `?website` | Get/Set website hosting config | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?website"` |
| `?logging` | Get/Set bucket logging config | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?logging"` |
| `?notification` | Get/Set notification config | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?notification"` |
| `?replication` | Get/Set cross-region replication | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?replication"` |
| `?tagging` | Get/Set bucket tag set | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?tagging"` |
| `?cors` | Get/Set CORS config | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?cors"` |
| `?policy` | Get/Set bucket policy | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?policy"` |
| `?analytics` | Manage advanced analytics | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?analytics"` |
| `?inventory` | Manage bucket inventory | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?inventory"` |
| `?metrics` | Manage bucket metrics | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?metrics"` |
| `?publicAccessBlock` | Block public access settings | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?publicAccessBlock"` |
| `?encryption` | Server-side encryption config | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?encryption"` |
| `?object-lock` | Object lock configuration | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?object-lock"` |
| `?location` | Get bucket region location | `./s3curl.py --id personal -- "https://my-bucket.s3.eu-north-1.amazonaws.com/?location"` |

### Object Lock Configuration Example

Get the Object Lock configuration for a bucket:

```bash
./s3curl.py \
  --id personal \
  -- \
  "https://my-bucket.s3.eu-north-1.amazonaws.com/?object-lock"
```

This returns XML like:
```xml
<GetObjectLockConfigurationOutput xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <ObjectLockConfiguration>
    <ObjectLockEnabled>Enabled</ObjectLockEnabled>
    <Rule>
      <DefaultRetention>
        <Mode>GOVERNANCE</Mode>
        <Days>30</Days>
      </DefaultRetention>
    </Rule>
  </ObjectLockConfiguration>
</GetObjectLockConfigurationOutput>
```

To set an Object Lock configuration, use `--put` with an XML file:

```bash
./s3curl.py \
  --id personal \
  --put object-lock-config.xml \
  --contentType application/xml \
  -- \
  "https://my-bucket.s3.eu-north-1.amazonaws.com/?object-lock"
```

### Bucket vs Object Operations

- **Bucket sub-resources**: `https://bucket.s3.region.amazonaws.com/?something`
- **Object operations**: `https://bucket.s3.region.amazonaws.com/key-name`

### Advanced Features

#### Upload with Content MD5 Verification

```bash
./s3curl.py \
  --id personal \
  --put important-file.bin \
  --calculateContentMd5 \
  -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/important-file.bin
```

#### Debug Request/Response

```bash
./s3curl.py \
  --id personal \
  --put myfile.txt \
  --saveRequest debug-output.txt \
  --debug \
  -- \
  https://my-bucket.s3.eu-north-1.amazonaws.com/myfile.txt
```

#### Add Custom Headers

```bash
./s3curl.py \
  --id personal \
  --put data.txt \
  -- \
  -H "Cache-Control: max-age=3600" \
  -H "Content-Encoding: gzip" \
  https://my-bucket.s3.eu-north-1.amazonaws.com/data.txt
```

### Complete Workflow Example

Here's a complete example showing upload, verification, download, and cleanup:

```bash
# 1. Upload a file
./s3curl.py \
  --id personal \
  --put somefile.bin \
  --contentType application/octet-stream \
  -- \
  https://test-bucket.s3.eu-north-1.amazonaws.com/somefile.bin

# 2. Verify upload with HEAD
./s3curl.py \
  --id personal \
  --head \
  -- \
  https://test-bucket.s3.eu-north-1.amazonaws.com/somefile.bin

# 3. Check bucket versioning
./s3curl.py \
  --id personal \
  -- \
  "https://test-bucket.s3.eu-north-1.amazonaws.com/?versioning"

# 4. Download the file
./s3curl.py \
  --id personal \
  -- \
  https://test-bucket.s3.eu-north-1.amazonaws.com/somefile.bin \
  > somefile-downloaded.bin

# 5. Clean up
./s3curl.py \
  --id personal \
  --delete \
  -- \
  https://test-bucket.s3.eu-north-1.amazonaws.com/somefile.bin
```

## Limitations

- **Memory usage**: The script loads entire files into memory for SHA-256 calculation, which may be problematic for very large files
- **No multipart uploads**: Does not support S3 multipart upload for large files
- **Custom endpoints**: May require manual region specification for CNAME or custom S3-compatible endpoints
- **Permissions**: Ensure your IAM user/role has appropriate S3 permissions (`GetObject`, `PutObject`, `DeleteObject`, `ListBucket`, etc.)

## Troubleshooting

### Common Issues

1. **403 Forbidden**: Check IAM permissions and ensure credentials are correct
2. **Region errors**: Use `--region` to specify the correct region manually
3. **Signature errors**: Ensure system clock is synchronized with AWS (within 15 minutes)
4. **Sub-resource access**: Ensure your IAM permissions include the specific bucket sub-resource operations (e.g., `s3:GetBucketVersioning`, `s3:GetObjectLockConfiguration`)

### Debug Tips

- Use `--saveRequest debug.txt` to inspect the raw HTTP request and response
- Use `--debug` for verbose logging of signature calculation
- Check AWS CloudTrail for detailed API call logs
- For bucket sub-resources, ensure the URL includes the `?` parameter correctly

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the unlicense 

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Use `--debug` and `--saveRequest` to gather diagnostic information
3. Open an issue on GitHub with the debug output (remove any sensitive information)

---

**Note**: This tool requires AWS Signature Version 4, making it compatible with all AWS regions, including newer regions that don't support the legacy Signature Version 2.
