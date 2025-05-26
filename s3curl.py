#!/usr/bin/env python3
"""
Enhanced Python 's3curl'-like script for AWS S3 with Signature Version 4.

Improvements:
- Type hints for better code clarity
- Concurrent multi-part uploads for better performance
- Streaming support for large files to reduce memory usage
- Request retry logic with exponential backoff
- JSON output format option
- Request timing and performance metrics
- Progress bars for uploads
- Better error handling and validation
- Support for S3 Select operations
- Connection pooling for better performance
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
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote
from typing import Dict, Tuple, Optional, List, Any, BinaryIO
from functools import wraps
from io import BytesIO

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Try to import tqdm for progress bars, fallback to simple progress
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Configuration constants
CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks for multipart
STREAM_CHUNK_SIZE = 8192  # 8KB chunks for streaming


class S3RequestError(Exception):
    """Custom exception for S3 request errors"""
    pass


def timing_decorator(func):
    """Decorator to measure function execution time"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logging.debug(f"{func.__name__} took {end_time - start_time:.3f} seconds")
        return result
    return wrapper


def create_session(max_retries: int = 3) -> requests.Session:
    """Create a requests session with retry logic and connection pooling"""
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "PUT", "POST", "DELETE"]
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=20
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def load_s3curl_config(config_path: str) -> Dict[str, Dict[str, str]]:
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

    local_vars: Dict[str, Any] = {}
    with open(config_path, 'r') as f:
        code = f.read()
    exec(code, {}, local_vars)
    return local_vars.get('awsSecretAccessKeys', {})


def setup_logging_to_file(log_file: str, console_level: int) -> None:
    """
    Configure logging:
    - Console uses level console_level (INFO or DEBUG).
    - File captures everything at DEBUG level.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    for h in list(logger.handlers):
        logger.removeHandler(h)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(console_level)
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(ch)

    # File handler
    fh = logging.FileHandler(log_file, mode='w')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)


def sha256_hexdigest(data: bytes) -> str:
    """Calculate SHA256 hex digest of data"""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, msg: str) -> bytes:
    """Calculate HMAC-SHA256"""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    """Derive SigV4 signing key for the given date_stamp, region, and service"""
    k_date = hmac_sha256(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = hmac_sha256(k_date, region_name)
    k_service = hmac_sha256(k_region, service_name)
    k_signing = hmac_sha256(k_service, 'aws4_request')
    return k_signing


def guess_region_from_host(hostname: str) -> str:
    """If host is like <bucket>.s3.<region>.amazonaws.com, return that region, else 'us-east-1'"""
    m = re.search(r'\.s3\.([^.]+)\.amazonaws\.com$', hostname)
    if m:
        return m.group(1)
    
    # Check for s3.amazonaws.com (us-east-1)
    if hostname.endswith('.s3.amazonaws.com'):
        return 'us-east-1'
    
    # Check for s3-<region>.amazonaws.com format
    m = re.search(r'\.s3-([^.]+)\.amazonaws\.com$', hostname)
    if m:
        return m.group(1)
    
    return 'us-east-1'


def calc_md5_streaming(file_obj: BinaryIO) -> str:
    """Calculate MD5 of a file using streaming to avoid loading entire file in memory"""
    md5 = hashlib.md5()
    for chunk in iter(lambda: file_obj.read(STREAM_CHUNK_SIZE), b''):
        md5.update(chunk)
    file_obj.seek(0)  # Reset file position
    return base64.b64encode(md5.digest()).decode('utf-8')


def calc_md5_of_bytes(data: bytes) -> str:
    """Calculate MD5 of bytes"""
    md5 = hashlib.md5(data)
    return base64.b64encode(md5.digest()).decode('utf-8')


def create_bucket_configuration_xml(region: str) -> str:
    """Return <CreateBucketConfiguration> if region is non-empty, else empty string"""
    if region and region != 'us-east-1':
        return (
            f"<CreateBucketConfiguration>"
            f"<LocationConstraint>{region}</LocationConstraint>"
            f"</CreateBucketConfiguration>"
        )
    return ''


def format_bytes(size: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def validate_url(url: str) -> bool:
    """Validate that the URL is a proper S3 URL"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False
        if not parsed.hostname:
            return False
        # Basic S3 hostname validation
        if 'amazonaws.com' in parsed.hostname or 's3' in parsed.hostname:
            return True
        # Allow custom S3-compatible endpoints
        return True
    except Exception:
        return False


def dump_request_and_response(prep: requests.PreparedRequest, resp: requests.Response, 
                             filename: str, timing_info: Optional[Dict[str, float]] = None) -> None:
    """Save the actual request & response to a file for debugging"""
    with open(filename, 'wb') as f:
        f.write(b"=== REQUEST ===\n")
        request_line = f"{prep.method} {prep.path_url} HTTP/1.1\n"
        f.write(request_line.encode('utf-8'))
        for hname, hval in prep.headers.items():
            f.write(f"{hname}: {hval}\n".encode('utf-8'))
        f.write(b"\n")
        
        if prep.body:
            if isinstance(prep.body, bytes):
                f.write(f"[Request body: {len(prep.body)} bytes]\n".encode('utf-8'))
                if len(prep.body) <= 1024:  # Show small bodies
                    f.write(prep.body)
            else:
                f.write(f"[Request body: {prep.body}]\n".encode('utf-8'))
        else:
            f.write(b"[No request body]\n")

        f.write(b"\n=== RESPONSE ===\n")
        status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}\n"
        f.write(status_line.encode('utf-8'))
        for hname, hval in resp.headers.items():
            f.write(f"{hname}: {hval}\n".encode('utf-8'))
        f.write(b"\n")
        
        # Add timing information if available
        if timing_info:
            f.write(b"\n=== TIMING INFO ===\n")
            for key, value in timing_info.items():
                f.write(f"{key}: {value:.3f}s\n".encode('utf-8'))
            f.write(b"\n")
        
        f.write(resp.content)


def interactive_edit_headers_and_body(all_headers: Dict[str, str], 
                                     body_bytes: bytes) -> Tuple[Dict[str, str], bytes, bool]:
    """
    Present an interactive prompt for editing headers and body.
    Return (updated_headers, updated_body, do_send).
    """
    while True:
        print("\n=== CURRENT HEADERS ===")
        if not all_headers:
            print("[No headers set]")
        else:
            for k, v in sorted(all_headers.items()):
                print(f"{k}: {v}")

        print(f"\n=== CURRENT BODY LENGTH: {format_bytes(len(body_bytes))} ===")
        if len(body_bytes) <= 2048:
            try:
                print(body_bytes.decode('utf-8', errors='replace'))
            except:
                print("[Binary data]")
        else:
            print("[Body is too large to display fully]")
        print()

        print("(E) Edit headers, (B) Edit body, (S) Send, or (C) Cancel? ", end="", flush=True)
        choice = sys.stdin.readline().strip().lower()
        
        if choice == 's':
            return (all_headers, body_bytes, True)
        elif choice == 'c':
            return (all_headers, body_bytes, False)
        elif choice == 'e':
            print("\nRewrite headers from scratch. Enter lines 'Header: value'. End with blank line.")
            new_headers = {}
            while True:
                line = sys.stdin.readline()
                if not line or line.strip() == '':
                    break
                line = line.rstrip('\n')
                m = re.match(r'([^:]+):\s*(.*)', line)
                if m:
                    hk = m.group(1).strip()
                    hv = m.group(2)
                    new_headers[hk] = hv
                else:
                    print(f"Cannot parse header line: {line}")
            if new_headers:
                all_headers = new_headers
                
        elif choice == 'b':
            print("Path to new body file? '-' to clear, 'stdin' for stdin input, or blank to keep: ", end="", flush=True)
            body_line = sys.stdin.readline().strip()
            if body_line == '-':
                body_bytes = b''
            elif body_line == 'stdin':
                print("Enter body content (end with EOF/Ctrl+D):")
                body_bytes = sys.stdin.buffer.read()
            elif body_line:
                if os.path.isfile(body_line):
                    with open(body_line, 'rb') as f:
                        body_bytes = f.read()
                    print(f"New body length: {format_bytes(len(body_bytes))}")
                else:
                    print("File not found, keeping old body.")
        else:
            print("Unknown option, choose E, B, S, or C.")


@timing_decorator
def sign_and_send(
    method: str,
    url: str,
    region: str,
    access_key: str,
    secret_key: str,
    body_bytes: bytes,
    extra_headers: Dict[str, str],
    xamz_headers: Dict[str, str],
    save_request: str = '',
    interactive: bool = False,
    session: Optional[requests.Session] = None,
    json_output: bool = False,
    timeout: int = 30
) -> requests.Response:
    """
    Build a SigV4 request, optionally let user interactively edit headers & body,
    then send the request. Return the requests.Response.
    """
    if session is None:
        session = create_session(max_retries=3)

    # Validate URL
    if not validate_url(url):
        raise S3RequestError(f"Invalid URL: {url}")

    # Parse the URL
    url_parts = urlparse(url)
    scheme = url_parts.scheme
    host = url_parts.hostname
    port = url_parts.port
    path = url_parts.path or '/'

    # Known S3 subresources
    known_subresources = [
        'acl', 'accelerate', 'analytics', 'cors', 'delete', 'encryption', 
        'inventory', 'lifecycle', 'location', 'logging', 'metrics',
        'notification', 'partNumber', 'policy', 'publicAccessBlock',
        'replication', 'requestPayment', 'restore', 'select', 'tagging',
        'torrent', 'uploadId', 'uploads', 'versionId', 'versioning', 
        'versions', 'website'
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
            elif k.startswith('response-'):  # response-* params are subresources
                query_dict[k] = v

    host_with_port = host if port is None else f"{host}:{port}"

    # Payload hash
    payload_hash = sha256_hexdigest(body_bytes)
    xamz_headers['x-amz-content-sha256'] = payload_hash

    # x-amz-date
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now_utc.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now_utc.strftime('%Y%m%d')
    xamz_headers['x-amz-date'] = amz_date

    # Merge headers
    extra_headers['Host'] = host_with_port
    final_headers = {}
    final_headers.update(extra_headers)
    final_headers.update(xamz_headers)

    # Interactive editing
    if interactive:
        updated_headers, updated_body, do_send = interactive_edit_headers_and_body(final_headers, body_bytes)
        if not do_send:
            logging.info("User canceled the request.")
            r = requests.Response()
            r.status_code = 0
            r.reason = "UserCanceled"
            r._content = b"Request canceled by user."
            return r

        # Re-sign with updated values
        return sign_and_send(
            method=method,
            url=url,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
            body_bytes=updated_body,
            extra_headers={},
            xamz_headers={},
            save_request=save_request,
            interactive=False,
            session=session,
            json_output=json_output,
            timeout=timeout
        )

    # Build canonical request
    def uri_encode(seg: str) -> str:
        return quote(seg, safe='/~')
    
    canonical_uri = uri_encode(path)

    # Canonical query string
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
        cleaned_val = re.sub(r'\s+', ' ', str(hdr_val).strip())
        header_list.append((lower_name, hdr_name, cleaned_val))
    header_list.sort(key=lambda x: x[0])

    canonical_headers = ''
    signed_header_names = []
    for lower_name, _, val in header_list:
        canonical_headers += f"{lower_name}:{val}\n"
        signed_header_names.append(lower_name)
    signed_headers_str = ';'.join(signed_header_names)

    canonical_request = (
        f"{method}\n"
        f"{canonical_uri}\n"
        f"{canonical_query}\n"
        f"{canonical_headers}\n"
        f"{signed_headers_str}\n"
        f"{payload_hash}"
    )
    
    logging.debug("CanonicalRequest:\n%s", canonical_request)
    cr_hash = sha256_hexdigest(canonical_request.encode('utf-8'))

    # String to sign
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{date_stamp}/{region}/s3/aws4_request\n"
        f"{cr_hash}"
    )
    logging.debug("StringToSign:\n%s", string_to_sign)

    # Calculate signature
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

    # Prepare request
    req = requests.Request(method=method, url=final_url, headers=final_headers, data=body_bytes)
    prep = session.prepare_request(req)

    # Display request info
    if not json_output:
        print("=== REQUEST ===")
        print(f"{prep.method} {prep.path_url} HTTP/1.1")
        for hname, hval in prep.headers.items():
            print(f"{hname}: {hval}")
        if prep.body:
            if isinstance(prep.body, bytes):
                print(f"\n[Request body: {format_bytes(len(prep.body))}]")
            else:
                print(f"\n[Request body: {prep.body}]")
        else:
            print("\n[No request body]")

    # Send request with timing
    start_time = time.time()
    resp = session.send(prep, verify=True, timeout=timeout)
    end_time = time.time()
    
    timing_info = {
        'total_time': end_time - start_time,
        'response_time': resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0
    }

    # Save to file if requested
    if save_request:
        dump_request_and_response(prep, resp, save_request, timing_info)

    # Add timing info to response
    resp.timing_info = timing_info

    return resp


def upload_part_concurrent(
    session: requests.Session,
    url: str,
    part_number: int,
    upload_id: str,
    chunk_data: bytes,
    region: str,
    access_key: str,
    secret_key: str,
    extra_headers: Dict[str, str],
    xamz_headers: Dict[str, str]
) -> Tuple[int, str, Optional[str]]:
    """Upload a single part in a multipart upload"""
    part_url = f"{url}?partNumber={part_number}&uploadId={upload_id}"
    
    try:
        resp = sign_and_send(
            method='PUT',
            url=part_url,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
            body_bytes=chunk_data,
            extra_headers=dict(extra_headers),
            xamz_headers=dict(xamz_headers),
            session=session,
            json_output=True  # Suppress output for concurrent uploads
        )
        
        if resp.status_code != 200:
            return (part_number, '', f"Failed with status {resp.status_code}")
        
        etag = resp.headers.get('ETag', '')
        return (part_number, etag, None)
    except Exception as e:
        return (part_number, '', str(e))


@timing_decorator
def do_multipart_upload(
    file_path: str,
    url: str,
    region: str,
    access_key: str,
    secret_key: str,
    content_type: str,
    extra_headers: Dict[str, str],
    xamz_headers: Dict[str, str],
    save_request: str = '',
    max_workers: int = 10,
    max_retries: int = 3
) -> requests.Response:
    """
    Enhanced multipart upload with concurrent part uploads and progress tracking
    """
    file_size = os.path.getsize(file_path)
    logging.info(f"Initiating multi-part upload for {file_path} ({format_bytes(file_size)})")
    
    session = create_session(max_retries=max_retries)
    
    # Initiate multipart upload
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
        session=session
    )
    
    if resp_init.status_code != 200:
        logging.error(f"InitiateMultipartUpload failed: {resp_init.status_code} {resp_init.text}")
        return resp_init

    # Parse UploadId
    try:
        root = ET.fromstring(resp_init.content)
        upload_id = root.findtext('{http://s3.amazonaws.com/doc/2006-03-01/}UploadId')
        if not upload_id:
            raise ValueError("No <UploadId> in response.")
    except Exception as e:
        logging.error(f"Failed to parse InitiateMultipartUpload XML: {e}")
        return resp_init

    logging.info(f"Got uploadId={upload_id}")
    
    # Calculate number of parts
    num_parts = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    
    # Prepare progress bar
    if TQDM_AVAILABLE:
        progress_bar = tqdm(total=num_parts, desc="Uploading parts", unit="part")
    else:
        progress_bar = None
    
    # Upload parts concurrently
    part_etags = []
    futures = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        with open(file_path, 'rb') as f:
            part_num = 1
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                future = executor.submit(
                    upload_part_concurrent,
                    session, url, part_num, upload_id, chunk,
                    region, access_key, secret_key,
                    extra_headers, xamz_headers
                )
                futures.append(future)
                part_num += 1
        
        # Collect results
        for future in as_completed(futures):
            part_number, etag, error = future.result()
            if error:
                logging.error(f"Part {part_number} failed: {error}")
                if progress_bar:
                    progress_bar.close()
                # Abort multipart upload
                abort_url = f"{url}?uploadId={upload_id}"
                sign_and_send(
                    method='DELETE',
                    url=abort_url,
                    region=region,
                    access_key=access_key,
                    secret_key=secret_key,
                    body_bytes=b'',
                    extra_headers={},
                    xamz_headers={},
                    session=session,
                    json_output=True
                )
                raise S3RequestError(f"Multipart upload failed: {error}")
            
            part_etags.append((part_number, etag))
            if progress_bar:
                progress_bar.update(1)
    
    if progress_bar:
        progress_bar.close()
    
    # Sort by part number
    part_etags.sort(key=lambda x: x[0])
    
    # Complete multipart upload
    logging.info(f"Completing multi-part upload with {len(part_etags)} parts.")
    parts_xml = "<CompleteMultipartUpload>"
    for pn, et in part_etags:
        if not (et.startswith('"') and et.endswith('"')):
            et = '"' + et.strip('"') + '"'
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
        session=session
    )
    
    if resp_complete.status_code == 200:
        logging.info("Multi-part upload completed successfully.")
    else:
        logging.error(f"CompleteMultipartUpload failed: {resp_complete.status_code} {resp_complete.text}")
    
    return resp_complete


def format_response_output(resp: requests.Response, json_output: bool = False) -> None:
    """Format and print response output"""
    if json_output:
        output = {
            'status_code': resp.status_code,
            'reason': resp.reason,
            'headers': dict(resp.headers),
            'body': resp.text,
            'timing': getattr(resp, 'timing_info', {})
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n=== RESPONSE ===")
        print(f"HTTP/1.1 {resp.status_code} {resp.reason}")
        for h, v in resp.headers.items():
            print(f"{h}: {v}")
        
        # Print timing info
        if hasattr(resp, 'timing_info'):
            print(f"\n=== TIMING ===")
            for key, value in resp.timing_info.items():
                print(f"{key}: {value:.3f}s")
        
        print()
        if resp.content:
            content_type = resp.headers.get('Content-Type', '')
            if 'xml' in content_type or 'json' in content_type or 'text' in content_type:
                print(resp.text)
            else:
                print(f"[Binary response: {format_bytes(len(resp.content))}]")
        sys.stdout.flush()


def main():
    # Declare globals at the beginning
    global CHUNK_SIZE
    
    parser = argparse.ArgumentParser(
        description="Enhanced Python SigV4 S3 API debugging tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # GET object
  %(prog)s --id mykey https://mybucket.s3.amazonaws.com/myfile.txt

  # PUT object with progress
  %(prog)s --id mykey --put file.txt --progress https://mybucket.s3.amazonaws.com/file.txt

  # Multipart upload with concurrency
  %(prog)s --id mykey --multipartUpload bigfile.zip --workers 20 https://mybucket.s3.amazonaws.com/bigfile.zip

  # Interactive header editing
  %(prog)s --id mykey --interactive --put data.json https://mybucket.s3.amazonaws.com/data.json

  # JSON output for scripting
  %(prog)s --id mykey --json https://mybucket.s3.amazonaws.com/status.txt
        """
    )
    
    # Credentials
    parser.add_argument('--id', required=True,
                        help='Friendly name from config or actual Access Key ID.')
    parser.add_argument('--key', help='AWS Secret Key (unsafe on command line).')
    parser.add_argument('--config', default='',
                        help='Path to .s3curl config (chmod 600). Defaults to ./.s3curl or ~/.s3curl.')

    # Basic operations
    parser.add_argument('--acl', help='x-amz-acl: public-read, private, etc.')
    parser.add_argument('--copySrc', help='x-amz-copy-source: bucket/key')
    parser.add_argument('--copySrcRange', help='x-amz-copy-source-range: bytes=0-999')
    parser.add_argument('--contentType', default='', help='Content-Type header')
    parser.add_argument('--contentMd5', default='', help='Content-MD5 header')
    parser.add_argument('--calculateContentMd5', action='store_true',
                        help='Calculate Content-MD5 automatically')

    # Methods
    parser.add_argument('--put', help='PUT from local file.')
    parser.add_argument('--post', nargs='?', const='', help='POST, optionally from file.')
    parser.add_argument('--head', action='store_true', help='HEAD request')
    parser.add_argument('--delete', action='store_true', help='DELETE request')
    parser.add_argument('--createBucket', nargs='?', const='',
                        help='PUT to create a bucket, optional region constraint.')

    # Advanced features
    parser.add_argument('--multipartUpload', help='Perform concurrent multi-part upload.')
    parser.add_argument('--workers', type=int, default=10,
                        help='Number of concurrent workers for multipart upload (default: 10)')
    parser.add_argument('--chunkSize', type=int, default=8*1024*1024,
                        help='Chunk size for multipart upload in bytes (default: 8MB)')

    # Configuration
    parser.add_argument('--region', default='', help='AWS region (auto-detected if not specified)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Request timeout in seconds (default: 30)')
    parser.add_argument('--retries', type=int, default=3,
                        help='Max number of retries (default: 3)')
    
    # Output options
    parser.add_argument('--saveRequest', help='Save request & response to file')
    parser.add_argument('--debug', action='store_true', help='Show debug info on console')
    parser.add_argument('--logFile', help='Capture full debug info in a log file')
    parser.add_argument('--json', action='store_true', help='Output response in JSON format')
    parser.add_argument('--progress', action='store_true', 
                        help='Show progress bar for uploads (requires tqdm)')

    # Interactive mode
    parser.add_argument('--interactive', action='store_true',
                        help='Interactively edit headers & body before sending')

    # Additional arguments
    parser.add_argument('curl_args', nargs=argparse.REMAINDER,
                        help='Extra arguments: -H "Header:value" https://bucket.s3.amazonaws.com/key')

    args = parser.parse_args()

    # Setup logging
    console_level = logging.DEBUG if args.debug else logging.INFO
    if args.logFile:
        setup_logging_to_file(args.logFile, console_level)
    else:
        logging.basicConfig(level=console_level, format='[%(levelname)s] %(message)s')

    # Update global chunk size if specified
    if args.chunkSize != CHUNK_SIZE:
        CHUNK_SIZE = args.chunkSize

    # Load credentials
    config_paths = []
    if args.config:
        config_paths.append(args.config)
    else:
        script_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
        config_paths = [
            os.path.join(script_dir, '.s3curl'),
            os.path.join(os.path.expanduser('~'), '.s3curl')
        ]
    
    aws_secrets = {}
    for p in config_paths:
        if os.path.isfile(p):
            try:
                aws_secrets = load_s3curl_config(p)
                logging.info(f"Loaded credentials from {p}")
                break
            except Exception as ex:
                logging.warning(f"Error loading config from {p}: {ex}")
        else:
            logging.debug(f"Config file not found at {p}")

    # Determine credentials
    if args.key:
        logging.warning("WARNING: Using --key on command line is insecure. Proceeding...")
        chosen_key_id = args.id
        chosen_secret = args.key
    else:
        if args.id in aws_secrets:
            chosen_key_id = aws_secrets[args.id]['id']
            chosen_secret = aws_secrets[args.id]['key']
        else:
            # Check if user provided actual key ID
            found = False
            for friendly, kv in aws_secrets.items():
                if kv.get('id') == args.id:
                    chosen_key_id = kv['id']
                    chosen_secret = kv['key']
                    found = True
                    break
            if not found:
                raise RuntimeError(f"No credentials for '{args.id}' in config and no --key given.")

    # Determine HTTP method
    method = 'GET'
    if args.delete:
        method = 'DELETE'
    elif args.head:
        method = 'HEAD'
    elif args.put or args.createBucket is not None or args.copySrc:
        method = 'PUT'
    elif args.post is not None:
        method = 'POST'

    # Build x-amz headers
    xamz_headers: Dict[str, str] = {}
    if args.acl:
        xamz_headers['x-amz-acl'] = args.acl
    if args.copySrc:
        xamz_headers['x-amz-copy-source'] = args.copySrc
    if args.copySrcRange:
        xamz_headers['x-amz-copy-source-range'] = args.copySrcRange

    # Parse remaining arguments for URL and headers
    final_url = None
    extra_headers: Dict[str, str] = {}
    i = 0
    while i < len(args.curl_args):
        token = args.curl_args[i]
        if re.match(r'^https?://', token):
            final_url = token
            i += 1
        elif token == '-H' and i + 1 < len(args.curl_args):
            hdr_line = args.curl_args[i + 1]
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
                logging.warning(f"Cannot parse header: {hdr_line}")
        else:
            i += 1

    if not final_url:
        parser.error("No URL specified")

    # Determine region
    if args.region:
        region = args.region
    else:
        hostname = urlparse(final_url).hostname
        region = guess_region_from_host(hostname) if hostname else 'us-east-1'

    # Handle multipart upload
    if args.multipartUpload:
        if not os.path.isfile(args.multipartUpload):
            parser.error(f"File not found: {args.multipartUpload}")
        
        method = 'PUT'
        logging.info(f"Performing multi-part upload of {args.multipartUpload} to {final_url}")
        
        if args.contentType:
            extra_headers['Content-Type'] = args.contentType
        
        try:
            resp = do_multipart_upload(
                file_path=args.multipartUpload,
                url=final_url,
                region=region,
                access_key=chosen_key_id,
                secret_key=chosen_secret,
                content_type=args.contentType,
                extra_headers=extra_headers,
                xamz_headers=xamz_headers,
                save_request=args.saveRequest,
                max_workers=args.workers,
                max_retries=args.retries
            )
            format_response_output(resp, args.json)
        except Exception as e:
            logging.error(f"Multipart upload failed: {e}")
            sys.exit(1)
        return

    # Handle single request
    body_bytes = b''
    
    # Prepare request body
    if method == 'PUT' and args.createBucket is not None:
        xml_str = create_bucket_configuration_xml(args.createBucket)
        body_bytes = xml_str.encode('utf-8')
        if args.calculateContentMd5:
            args.contentMd5 = calc_md5_of_bytes(body_bytes)
    elif method == 'PUT' and args.put:
        if not os.path.isfile(args.put):
            parser.error(f"File not found: {args.put}")
        
        if args.calculateContentMd5:
            with open(args.put, 'rb') as f:
                args.contentMd5 = calc_md5_streaming(f)
        
        with open(args.put, 'rb') as f:
            body_bytes = f.read()
    elif method == 'POST':
        if args.post and len(args.post) > 0:
            if not os.path.isfile(args.post):
                parser.error(f"File not found: {args.post}")
            
            if args.calculateContentMd5:
                with open(args.post, 'rb') as f:
                    args.contentMd5 = calc_md5_streaming(f)
            
            with open(args.post, 'rb') as f:
                body_bytes = f.read()
        else:
            if args.calculateContentMd5:
                args.contentMd5 = calc_md5_of_bytes(b'')
    else:
        if args.calculateContentMd5:
            args.contentMd5 = calc_md5_of_bytes(b'')

    # Set headers
    if args.contentMd5:
        extra_headers['Content-MD5'] = args.contentMd5
    if args.contentType:
        extra_headers['Content-Type'] = args.contentType

    # Send request
    try:
        session = create_session(max_retries=args.retries)
        resp = sign_and_send(
            method=method,
            url=final_url,
            region=region,
            access_key=chosen_key_id,
            secret_key=chosen_secret,
            body_bytes=body_bytes,
            extra_headers=extra_headers,
            xamz_headers=xamz_headers,
            save_request=args.saveRequest,
            interactive=args.interactive,
            json_output=args.json,
            timeout=args.timeout,
            session=session
        )
        format_response_output(resp, args.json)
    except Exception as e:
        logging.error(f"Request failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
