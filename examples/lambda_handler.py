"""
AWS Lambda handler for virus scanning S3 objects using ICAP.

This example demonstrates how to use PyCap in an AWS Lambda function
to scan newly uploaded S3 objects for viruses.

Environment Variables:
    ICAP_HOST: Hostname of the ICAP antivirus server
    ICAP_PORT: Port of the ICAP server (default: 1344)
    ICAP_SERVICE: ICAP service name (default: "avscan")

Requirements:
    - boto3
    - aws-lambda-powertools
    - pycap
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.exceptions import ClientError

from pycap import IcapClient
from pycap.exception import IcapConnectionError, IcapTimeoutError

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

# Initialize logger
logger = Logger(service="virus-scanner")

# Initialize S3 client
s3_client: S3Client = boto3.client("s3")

# Configuration from environment
ICAP_HOST = os.environ.get("ICAP_HOST", "localhost")
ICAP_PORT = int(os.environ.get("ICAP_PORT", "1344"))
ICAP_SERVICE = os.environ.get("ICAP_SERVICE", "avscan")


class VirusFoundException(Exception):
    """Raised when a virus is detected in the scanned content."""

    def __init__(self, bucket: str, key: str, message: str = "Virus detected"):
        self.bucket = bucket
        self.key = key
        self.message = message
        super().__init__(f"{message} in s3://{bucket}/{key}")


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
    # Parse S3 event
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

        # Download object from S3
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

        # Scan content using ICAP
        try:
            with IcapClient(ICAP_HOST, port=ICAP_PORT) as client:
                scan_response = client.scan_bytes(
                    content,
                    service=ICAP_SERVICE,
                    filename=key,
                )

                if scan_response.is_no_modification:
                    # No virus found - content is clean
                    logger.info(
                        "No virus detected - content is clean",
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
                    # Virus detected
                    logger.error(
                        "Virus detected in S3 object",
                        extra={
                            "bucket": bucket,
                            "key": key,
                            "status_code": scan_response.status_code,
                            "headers": dict(scan_response.headers),
                        },
                    )
                    raise VirusFoundException(bucket=bucket, key=key)

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
