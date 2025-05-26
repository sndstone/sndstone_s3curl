#!/usr/bin/env python3
"""
A Python 's3curl'-like script for AWS S3 with Signature Version 4, 
debugging, interactive editing, multi-part upload, and detailed logging.

Key Features:
1) GET/PUT/POST/HEAD/DELETE single requests with SigV4
2) Interactive editing of *all* headers & body before sending (single requests only)
3) Multi-part upload (sequential) if --multipartUpload <file> is used
4) Logs all debug info to a file if --logFile is specified
5) Optionally save the final single request & response to --saveRequest

No references to 'battery_report.html' remain; the script prints 
the *actual* request (method/path) every time.
"""

import sys
import os
import argparse
import logging
import datetime
import re
import hmac
import hashlib
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, quote
import requests

# Each multi-part chunk is 8MB by default
CHUNK_SIZE = 8 * 1024 * 1024

def load_s3curl_config(config_path):
    """
    Load a Python-format .s3curl file that defines:
        awsSecretAccessKeys = {
            'friendlyName': {'id': 'AKIA...', 'key': '...'},
            ...
        }
    Must be chmod 600 & owned by the user.
    """
    if not os.path.isfile(config_path):
        return {}
    st = os.stat(config_path)
    if st.st_uid != os.getuid():
        raise PermissionError(f"Refusing to read credentials from {config_path}: not owned by current user.")
    mode = st.st_mode & 0o777
    if (mode & 0o077) != 0:
        raise PermissionError(f"Refusing to read credentials from {config_path}: file must have mode 600.")

    local_vars = {}
    with open(config_path, 'r') as f:
        code = f.read()
    exec(code, {}, local_vars)
    return local_vars.get('awsSecretAccessKeys', {})


def setup_logging_to_file(log_file: str, console_level: int):
    """
    Configure logging:
    - Console uses level console_level (INFO or DEBUG).
    - File captures everything at DEBUG level.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # capture all events

    # Remove existing handlers
    for h in list(logger.handlers):
        logger.removeHandler(h)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(console_level)
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(ch)

    # File handler
    fh = logging.FileHandler(log_file, mode='w')  # overwrite
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)


def sha256_hexdigest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    """
    Derive SigV4 signing key for the given date_stamp, region, and service (normally 's3').
    """
    k_date = hmac_sha256(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = hmac_sha256(k_date, region_name)
    k_service = hmac_sha256(k_region, service_name)
    k_signing = hmac_sha256(k_service, 'aws4_request')
    return k_signing


def guess_region_from_host(hostname: str) -> str:
    """
    If host is like <bucket>.s3.<region>.amazonaws.com, return that region, else 'us-east-1'.
    """
    m = re.search(r'\.s3\.([^.]+)\.amazonaws\.com$', hostname)
    if m:
        return m.group(1)
    return 'us-east-1'


def calc_md5_of_file(file_path: str) -> str:
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
    return base64.b64encode(md5.digest()).decode('utf-8')


def calc_md5_of_string(s: str) -> str:
    md5 = hashlib.md5(s.encode('utf-8'))
    return base64.b64encode(md5.digest()).decode('utf-8')


def create_bucket_configuration_xml(region: str) -> str:
    """
    Return <CreateBucketConfiguration> if region is non-empty, else empty string.
    """
    if region:
        return (
            f"<CreateBucketConfiguration>"
            f"<LocationConstraint>{region}</LocationConstraint>"
            f"</CreateBucketConfiguration>"
        )
    return ''


def dump_request_and_response(prep: requests.PreparedRequest, resp: requests.Response, filename: str):
    """
    Save the actual request & response to a file for debugging.
    """
    with open(filename, 'wb') as f:
        f.write(b"=== REQUEST ===\n")
        request_line = f"{prep.method} {prep.path_url} HTTP/1.1\n"
        f.write(request_line.encode('utf-8'))
        for hname, hval in prep.headers.items():
            f.write(f"{hname}: {hval}\n".encode('utf-8'))
        f.write(b"\n")
        if prep.body:
            if isinstance(prep.body, bytes):
                f.write(prep.body)
            else:
                f.write(str(prep.body).encode('utf-8'))
        else:
            f.write(b"[No request body]\n")

        f.write(b"\n=== RESPONSE ===\n")
        status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}\n"
        f.write(status_line.encode('utf-8'))
        for hname, hval in resp.headers.items():
            f.write(f"{hname}: {hval}\n".encode('utf-8'))
        f.write(b"\n")
        f.write(resp.content)


def interactive_edit_headers_and_body(all_headers: dict, body_bytes: bytes) -> (dict, bytes, bool):
    """
    Present an interactive prompt for editing *all* headers from scratch + body. 
    Return (updated_headers, updated_body, do_send).
    If user cancels, do_send = False.
    """
    while True:
        print("\n=== CURRENT HEADERS ===")
        if not all_headers:
            print("[No headers set]")
        else:
            for k, v in all_headers.items():
                print(f"{k}: {v}")

        print("\n=== CURRENT BODY LENGTH:", len(body_bytes))
        if len(body_bytes) <= 2048:
            try:
                print(body_bytes.decode('utf-8', errors='replace'))
            except:
                print("[Binary data]")
        else:
            print("[Body is too large to display fully]")
        print()

        print("(E) Edit, (S) Send, or (C) Cancel? ", end="", flush=True)
        choice = sys.stdin.readline().strip().lower()
        if choice == 's':
            # Send
            return (all_headers, body_bytes, True)
        elif choice == 'c':
            # Cancel
            return (all_headers, body_bytes, False)
        elif choice == 'e':
            # Edit
            print("Rewrite headers from scratch. Enter lines 'Header: value'. End with blank line.")
            new_headers = {}
            lines_collected = []
            while True:
                line = sys.stdin.readline()
                if not line:
                    # EOF or something
                    break
                line = line.rstrip('\n')
                if line == '':
                    break
                lines_collected.append(line)
            if lines_collected:
                for ln in lines_collected:
                    m = re.match(r'([^:]+):\s*(.*)', ln)
                    if m:
                        hk = m.group(1).strip()
                        hv = m.group(2)
                        new_headers[hk] = hv
                    else:
                        print(f"Cannot parse header line: {ln}")
                all_headers = new_headers

            # Edit body
            print("Path to new body file? '-' to clear, or blank to keep existing: ", end="", flush=True)
            body_line = sys.stdin.readline().strip()
            if body_line == '-':
                body_bytes = b''
            elif body_line:
                if os.path.isfile(body_line):
                    body_bytes = open(body_line, 'rb').read()
                    print("New body length:", len(body_bytes))
                else:
                    print("File not found, keeping old body.")
        else:
            print("Unknown option, choose E, S, or C.")
    # end while


def sign_and_send(
    method: str,
    url: str,
    region: str,
    access_key: str,
    secret_key: str,
    body_bytes: bytes,
    extra_headers: dict,
    xamz_headers: dict,
    save_request: str = '',
    interactive: bool = False
) -> requests.Response:
    """
    Build a SigV4 request, optionally let user interactively edit all headers & body,
    then do the real send (unless canceled). Return the requests.Response.
    """
    session = requests.Session()

    # parse the URL
    url_parts = urlparse(url)
    scheme = url_parts.scheme
    host = url_parts.hostname
    port = url_parts.port
    path = url_parts.path or '/'

    # Known subresources
    known_subresources = [
        'acl', 'delete', 'location', 'logging', 'notification',
        'partNumber', 'policy', 'requestPayment', 'response-cache-control',
        'response-content-disposition', 'response-content-encoding',
        'response-content-language', 'response-content-type', 'response-expires',
        'torrent', 'uploadId', 'uploads', 'versionId', 'versioning', 'versions',
        'website', 'lifecycle', 'restore'
    ]
    query_dict = {}
    if url_parts.query:
        for kvp in url_parts.query.split('&'):
            if '=' in kvp:
                k, v = kvp.split('=', 1)
            else:
                k, v = kvp, ''
            if k in known_subresources:
                query_dict[k] = v

    host_with_port = host if port is None else f"{host}:{port}"

    # Step 1: payload hash
    payload_hash = sha256_hexdigest(body_bytes)
    xamz_headers['x-amz-content-sha256'] = payload_hash

    # Step 2: x-amz-date
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now_utc.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now_utc.strftime('%Y%m%d')
    xamz_headers['x-amz-date'] = amz_date

    # Merge headers
    extra_headers['Host'] = host_with_port
    final_headers = {}
    for k, v in extra_headers.items():
        final_headers[k] = v
    for k, v in xamz_headers.items():
        final_headers[k] = v

    # If interactive => let user rewrite everything
    if interactive:
        updated_headers, updated_body, do_send = interactive_edit_headers_and_body(final_headers, body_bytes)
        if not do_send:
            # user canceled
            logging.info("User canceled the request.")
            r = requests.Response()
            r.status_code = 0
            r.reason = "UserCanceled"
            r._content = b"Request canceled by user."
            return r

        # user changed headers/body, so we must re-sign properly
        # We'll call sign_and_send again with interactive=False 
        # to avoid infinite loop. Now we pass the updated values.
        return sign_and_send(
            method=method,
            url=url,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
            body_bytes=updated_body,
            extra_headers={},  # discard old to avoid merges
            xamz_headers={},
            save_request=save_request,
            interactive=False
        )

    # Build the canonical request
    def uri_encode(seg: str) -> str:
        return quote(seg, safe='/~')
    canonical_uri = uri_encode(path)

    # Build the canonical query
    qs_parts = []
    for k in sorted(query_dict.keys()):
        v = query_dict[k]
        ek = quote(k, safe='~')
        ev = quote(v, safe='~')
        qs_parts.append(f"{ek}={ev}" if v else ek)
    canonical_query = '&'.join(qs_parts)

    # Sort headers
    header_list = []
    for hdr_name, hdr_val in final_headers.items():
        lower_name = hdr_name.lower().strip()
        cleaned_val = re.sub(r'\s+', ' ', hdr_val.strip())
        header_list.append((lower_name, hdr_name, cleaned_val))
    header_list.sort(key=lambda x: x[0])

    chs = ''
    signed_header_names = []
    for lower_name, real_name, val in header_list:
        chs += f"{lower_name}:{val}\n"
        signed_header_names.append(lower_name)
    signed_headers_str = ';'.join(signed_header_names)

    canonical_request = (
        f"{method}\n"
        f"{canonical_uri}\n"
        f"{canonical_query}\n"
        f"{chs}\n"
        f"{signed_headers_str}\n"
        f"{payload_hash}"
    )
    logging.debug("CanonicalRequest:\n%s", canonical_request)
    cr_hash = sha256_hexdigest(canonical_request.encode('utf-8'))

    # StringToSign
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{date_stamp}/{region}/s3/aws4_request\n"
        f"{cr_hash}"
    )
    logging.debug("StringToSign:\n%s", string_to_sign)

    # Derive signature
    signing_key = get_signature_key(secret_key, date_stamp, region, 's3')
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    auth_val = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, "
        f"Signature={signature}"
    )
    final_headers['Authorization'] = auth_val

    # Build final URL
    if canonical_query:
        final_url = f"{scheme}://{host_with_port}{canonical_uri}?{canonical_query}"
    else:
        final_url = f"{scheme}://{host_with_port}{canonical_uri}"

    # Prepare & show the actual request
    req = requests.Request(method=method, url=final_url, headers=final_headers, data=body_bytes)
    prep = session.prepare_request(req)

    # Print out the *real* request about to be sent
    # (no more leftover "HEAD /battery_report.html" references)
    print("=== REQUEST ===")
    print(f"{prep.method} {prep.path_url} HTTP/1.1")
    for hname, hval in prep.headers.items():
        print(f"{hname}: {hval}")
    if prep.body:
        if isinstance(prep.body, bytes):
            print(f"\n[Request body: {len(prep.body)} bytes]")
        else:
            print(f"\n[Request body: {prep.body}]")
    else:
        print("\n[No request body]")

    # Send
    resp = session.send(prep, verify=True)

    # Save to file if needed
    if save_request:
        dump_request_and_response(prep, resp, save_request)

    return resp


def do_multipart_upload(file_path: str,
                        url: str,
                        region: str,
                        access_key: str,
                        secret_key: str,
                        content_type: str,
                        extra_headers: dict,
                        xamz_headers: dict,
                        save_request: str = ''):
    """
    Basic sequential multi-part upload. No interactive editing.
    """
    logging.info("Initiating multi-part upload for %s", file_path)
    initiate_url = f"{url}?uploads"
    resp_init = sign_and_send(
        method='POST',
        url=initiate_url,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        body_bytes=b'',
        extra_headers=dict(extra_headers),
        xamz_headers=dict(xamz_headers),
        save_request=''
    )
    if resp_init.status_code != 200:
        logging.error("InitiateMultipartUpload failed: %d %s", resp_init.status_code, resp_init.text)
        return resp_init

    # parse the UploadId
    try:
        root = ET.fromstring(resp_init.content)
        upload_id = root.findtext('{http://s3.amazonaws.com/doc/2006-03-01/}UploadId')
        if not upload_id:
            raise ValueError("No <UploadId> in response.")
    except Exception as e:
        logging.error("Failed to parse InitiateMultipartUpload XML: %s", e)
        return resp_init

    logging.info("Got uploadId=%s", upload_id)
    part_etags = []
    part_num = 1

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            logging.info("Uploading partNumber=%d, size=%d", part_num, len(chunk))
            part_url = f"{url}?partNumber={part_num}&uploadId={upload_id}"
            resp_part = sign_and_send(
                method='PUT',
                url=part_url,
                region=region,
                access_key=access_key,
                secret_key=secret_key,
                body_bytes=chunk,
                extra_headers=dict(extra_headers),
                xamz_headers=dict(xamz_headers),
                save_request=''
            )
            if resp_part.status_code != 200:
                logging.error("UploadPart %d failed: %d", part_num, resp_part.status_code)
                return resp_part
            etag = resp_part.headers.get('ETag', '')
            part_etags.append((part_num, etag))
            part_num += 1

    logging.info("Completing multi-part upload with %d parts.", len(part_etags))
    parts_xml = "<CompleteMultipartUpload>"
    for pn, et in part_etags:
        if not (et.startswith('"') and et.endswith('"')):
            et = f"\"{et.strip('\"')}\""
        parts_xml += f"<Part><PartNumber>{pn}</PartNumber><ETag>{et}</ETag></Part>"
    parts_xml += "</CompleteMultipartUpload>"

    complete_url = f"{url}?uploadId={upload_id}"
    resp_complete = sign_and_send(
        method='POST',
        url=complete_url,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        body_bytes=parts_xml.encode('utf-8'),
        extra_headers=dict(extra_headers),
        xamz_headers=dict(xamz_headers),
        save_request=''
    )
    if resp_complete.status_code == 200:
        logging.info("Multi-part upload completed successfully.")
    else:
        logging.error("CompleteMultipartUpload failed: %d %s", resp_complete.status_code, resp_complete.text)
    return resp_complete


def main():
    parser = argparse.ArgumentParser(description="A Python SigV4 's3curl' style debugging script.")
    # Credentials
    parser.add_argument('--id', required=True,
                        help='Friendly name from config or actual Access Key ID.')
    parser.add_argument('--key', help='AWS Secret Key (unsafe on command line).')
    parser.add_argument('--config', default='',
                        help='Path to .s3curl config (chmod 600). Defaults to ./.s3curl or ~/ .s3curl.')

    # Basic s3curl flags
    parser.add_argument('--acl', help='x-amz-acl: public-read, etc.')
    parser.add_argument('--copySrc', help='x-amz-copy-source: bucket/key')
    parser.add_argument('--copySrcRange', help='x-amz-copy-source-range: bytes=0-999')
    parser.add_argument('--contentType', default='', help='Content-Type header')
    parser.add_argument('--contentMd5', default='', help='Content-MD5 header')
    parser.add_argument('--calculateContentMd5', action='store_true')

    # Single-shot actions
    parser.add_argument('--put', help='PUT from local file.')
    parser.add_argument('--post', nargs='?', const='', help='POST, optionally from file.')
    parser.add_argument('--head', action='store_true')
    parser.add_argument('--delete', action='store_true')
    parser.add_argument('--createBucket', nargs='?', const='',
                        help='PUT to create a bucket, optional region constraint.')

    # Multi-part
    parser.add_argument('--multipartUpload', help='Perform multi-part upload from local file (no interactive editing).')

    # Region & logging
    parser.add_argument('--region', default='', help='Override region if not deduced from host.')
    parser.add_argument('--saveRequest', help='Save final single request & response to file.')
    parser.add_argument('--debug', action='store_true', help='Show debug info on console.')
    parser.add_argument('--logFile', help='Capture full debug info in a log file.')

    # Interactive
    parser.add_argument('--interactive', action='store_true',
                        help='Allow user to edit all headers & body before sending (single requests only).')

    parser.add_argument('curl_args', nargs=argparse.REMAINDER,
                        help='Extra arguments after --, e.g. -H "Header:..." https://bucket.s3.amazonaws.com/key')

    args = parser.parse_args()

    # Logging
    console_level = logging.DEBUG if args.debug else logging.INFO
    if args.logFile:
        setup_logging_to_file(args.logFile, console_level)
    else:
        logging.basicConfig(level=console_level, format='[%(levelname)s] %(message)s')

    # Load config
    config_paths = []
    if args.config:
        config_paths.append(args.config)
    else:
        script_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
        local_dotfile = os.path.join(script_dir, '.s3curl')
        home_dotfile = os.path.join(os.path.expanduser('~'), '.s3curl')
        config_paths = [local_dotfile, home_dotfile]
    aws_secrets = {}
    for p in config_paths:
        if os.path.isfile(p):
            try:
                aws_secrets = load_s3curl_config(p)
                break
            except Exception as ex:
                logging.debug("Error loading config from %s: %s", p, ex)

    # Credentials
    if args.key:
        logging.warning("WARNING: Using --key on command line is insecure. Waiting 5s or Ctrl-C to abort...")
        import time
        time.sleep(5)
        chosen_key_id = args.id
        chosen_secret = args.key
    else:
        if args.id in aws_secrets:
            chosen_key_id = aws_secrets[args.id]['id']
            chosen_secret = aws_secrets[args.id]['key']
        else:
            # Possibly user typed actual KeyID
            found = False
            for friendly, kv in aws_secrets.items():
                if kv.get('id') == args.id:
                    chosen_key_id = kv['id']
                    chosen_secret = kv['key']
                    found = True
                    break
            if not found:
                raise RuntimeError(f"No credentials for {args.id} in config and no --key given.")

    # Determine method
    method = 'GET'
    if args.delete:
        method = 'DELETE'
    elif args.head:
        method = 'HEAD'
    elif args.put or args.createBucket or args.copySrc:
        method = 'PUT'
    elif args.post is not None:
        method = 'POST'

    # x-amz- headers
    xamz_headers = {}
    if args.acl:
        xamz_headers['x-amz-acl'] = args.acl
    if args.copySrc:
        xamz_headers['x-amz-copy-source'] = args.copySrc
    if args.copySrcRange:
        xamz_headers['x-amz-copy-source-range'] = f"bytes={args.copySrcRange}"

    if args.calculateContentMd5 and args.contentMd5:
        raise RuntimeError("Cannot specify both --contentMd5 and --calculateContentMd5")

    # Parse leftover arguments to find a URL and optional -H "Header: value"
    final_url = None
    extra_headers = {}
    i = 0
    while i < len(args.curl_args):
        token = args.curl_args[i]
        if re.match(r'^https?://', token):
            final_url = token
            i += 1
        elif token == '-H':
            if i + 1 < len(args.curl_args):
                hdr_line = args.curl_args[i+1]
                i += 2
                m = re.match(r'([^:]+):\s*(.*)', hdr_line)
                if m:
                    hname, hval = m.group(1), m.group(2)
                    if hname.lower().startswith('x-amz-'):
                        lh = hname.lower()
                        if lh in xamz_headers:
                            xamz_headers[lh] += f",{hval}"
                        else:
                            xamz_headers[lh] = hval
                    else:
                        extra_headers[hname] = hval
                else:
                    logging.warning("Cannot parse header: %s", hdr_line)
            else:
                i += 1
        else:
            i += 1

    # If we do multi-part, we still need a URL:
    if not final_url and not args.multipartUpload:
        raise RuntimeError("No URL found (and no multi-part upload specified).")

    # Determine region
    if args.region:
        region = args.region
    else:
        if final_url:
            hostname = urlparse(final_url).hostname
            region = guess_region_from_host(hostname) if hostname else 'us-east-1'
        else:
            region = 'us-east-1'

    # Multi-part path
    if args.multipartUpload:
        if method != 'PUT':
            method = 'PUT'
        logging.info("Performing multi-part upload of %s to %s", args.multipartUpload, final_url)
        if args.contentType:
            extra_headers['Content-Type'] = args.contentType
        # We skip part-level MD5. 
        resp_multi = do_multipart_upload(
            file_path=args.multipartUpload,
            url=final_url,
            region=region,
            access_key=chosen_key_id,
            secret_key=chosen_secret,
            content_type=args.contentType,
            extra_headers=extra_headers,
            xamz_headers=xamz_headers,
            save_request=args.saveRequest if args.saveRequest else ''
        )
        print(f"HTTP/1.1 {resp_multi.status_code} {resp_multi.reason}")
        for h, v in resp_multi.headers.items():
            print(f"{h}: {v}")
        print()
        sys.stdout.write(resp_multi.text)
        sys.stdout.flush()
        return

    # Single request path
    body_bytes = b''
    if method == 'PUT' and args.createBucket is not None:
        xml_str = create_bucket_configuration_xml(args.createBucket)
        body_bytes = xml_str.encode('utf-8')
        if args.calculateContentMd5:
            args.contentMd5 = calc_md5_of_string(xml_str)
    elif method == 'PUT' and args.put:
        if args.calculateContentMd5:
            args.contentMd5 = calc_md5_of_file(args.put)
        body_bytes = open(args.put, 'rb').read()
    elif method == 'POST':
        if args.post and len(args.post) > 0:
            if args.calculateContentMd5:
                args.contentMd5 = calc_md5_of_file(args.post)
            body_bytes = open(args.post, 'rb').read()
        else:
            if args.calculateContentMd5:
                args.contentMd5 = calc_md5_of_string('')
    else:
        if args.calculateContentMd5:
            args.contentMd5 = calc_md5_of_string('')

    if args.contentMd5:
        extra_headers['Content-MD5'] = args.contentMd5
    if args.contentType:
        extra_headers['Content-Type'] = args.contentType

    resp = sign_and_send(
        method=method,
        url=final_url,
        region=region,
        access_key=chosen_key_id,
        secret_key=chosen_secret,
        body_bytes=body_bytes,
        extra_headers=extra_headers,
        xamz_headers=xamz_headers,
        save_request=args.saveRequest if args.saveRequest else '',
        interactive=args.interactive
    )

    # Print final result
    print(f"HTTP/1.1 {resp.status_code} {resp.reason}")
    for hh, hv in resp.headers.items():
        print(f"{hh}: {hv}")
    print()
    sys.stdout.write(resp.text)
    sys.stdout.flush()


if __name__ == '__main__':
    main()
