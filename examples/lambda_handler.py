"""
AWS Lambda handler for virus scanning S3 objects using ICAP.

This example demonstrates how to use python-icap in an AWS Lambda function
to scan newly uploaded S3 objects for viruses.

Environment Variables:
    ICAP_HOST: Hostname of the ICAP antivirus server
    ICAP_PORT: Port of the ICAP server (default: 1344)
    ICAP_SERVICE: ICAP service name (default: "avscan")

Requirements:
    - boto3
    - aws-lambda-powertools
    - python-icap
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.exceptions import ClientError

from icap import IcapClient
from icap.exception import IcapConnectionError, IcapTimeoutError

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

logger = Logger(service="virus-scanner")
s3_client: S3Client = boto3.client("s3")

ICAP_HOST = os.environ.get("ICAP_HOST", "localhost")
ICAP_PORT = int(os.environ.get("ICAP_PORT", "1344"))
ICAP_SERVICE = os.environ.get("ICAP_SERVICE", "avscan")


class VirusFoundException(Exception):
    """Raised when a virus is detected in the scanned content."""

    def __init__(
        self,
        bucket: str,
        key: str,
        virus_name: str | None = None,
    ):
        self.bucket = bucket
        self.key = key
        self.virus_name = virus_name
        message = f"Virus detected: {virus_name}" if virus_name else "Virus detected"
        super().__init__(f"{message} in s3://{bucket}/{key}")


def _extract_virus_name(headers: dict[str, str]) -> str | None:
    """
    Extract virus/threat name from ICAP response headers.

    Different ICAP servers use different headers for reporting threats.
    This function checks common header names used by popular AV engines.
    """
    threat_headers = [
        "X-Virus-ID",
        "X-Infection-Found",
        "X-Violations-Found",
        "X-Threat-Name",
    ]
    for header in threat_headers:
        if header in headers:
            return headers[header]
    return None


@logger.inject_lambda_context
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    Lambda handler for S3 object virus scanning.

    Triggered by S3 CreateObject events. Downloads the object and scans
    it using an ICAP antivirus server.

    Args:
        event: S3 event containing bucket and key information
        context: Lambda context

    Returns:
        dict with scan results

    Raises:
        VirusFoundException: If a virus is detected in the object
    """
    records = event.get("Records", [])
    if not records:
        logger.warning("No records in event")
        return {"status": "no_records"}

    results = []

    for record in records:
        s3_info = record.get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name")
        key = s3_info.get("object", {}).get("key")

        if not bucket or not key:
            logger.warning("Missing bucket or key in record", extra={"record": record})
            continue

        logger.info("Processing S3 object", extra={"bucket": bucket, "key": key})

        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
            content = response["Body"].read()
            content_length = len(content)
            logger.info(
                "Downloaded S3 object",
                extra={"bucket": bucket, "key": key, "size_bytes": content_length},
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.exception(
                "Failed to download S3 object",
                extra={"bucket": bucket, "key": key, "error_code": error_code},
            )
            raise

        try:
            with IcapClient(ICAP_HOST, port=ICAP_PORT) as client:
                scan_response = client.scan_bytes(
                    content,
                    service=ICAP_SERVICE,
                    filename=key,
                )

                if scan_response.is_no_modification:
                    logger.info(
                        "Scan complete - no threats detected",
                        extra={
                            "bucket": bucket,
                            "key": key,
                            "status_code": scan_response.status_code,
                        },
                    )
                    results.append(
                        {
                            "bucket": bucket,
                            "key": key,
                            "status": "clean",
                        }
                    )
                else:
                    headers = dict(scan_response.headers)
                    virus_name = _extract_virus_name(headers)
                    logger.error(
                        "Threat detected in S3 object",
                        extra={
                            "bucket": bucket,
                            "key": key,
                            "virus_name": virus_name,
                            "status_code": scan_response.status_code,
                            "headers": headers,
                        },
                    )
                    raise VirusFoundException(
                        bucket=bucket,
                        key=key,
                        virus_name=virus_name,
                    )

        except (IcapConnectionError, IcapTimeoutError):
            logger.exception(
                "ICAP server connection error",
                extra={"bucket": bucket, "key": key, "icap_host": ICAP_HOST},
            )
            raise

    return {
        "status": "success",
        "scanned_objects": len(results),
        "results": results,
    }
