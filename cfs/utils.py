"""Utility functions for Cloud Forensic Snapshot."""

import logging
from typing import Callable, Any, Type
import time

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

# Define cloud-specific transient exceptions if libraries are present
RETRIABLE_EXCEPTIONS = []

# AWS
try:
    from botocore.exceptions import ClientError, BotoCoreError
    RETRIABLE_EXCEPTIONS.append(ClientError)
    RETRIABLE_EXCEPTIONS.append(BotoCoreError)
except ImportError:
    pass

# Azure
try:
    from azure.core.exceptions import ServiceRequestError, ServiceResponseError, HttpResponseError
    RETRIABLE_EXCEPTIONS.append(ServiceRequestError)
    RETRIABLE_EXCEPTIONS.append(ServiceResponseError)
    RETRIABLE_EXCEPTIONS.append(HttpResponseError)
except ImportError:
    pass

# GCP
try:
    from google.api_core.exceptions import GoogleAPICallError, RetryError
    RETRIABLE_EXCEPTIONS.append(GoogleAPICallError)
    RETRIABLE_EXCEPTIONS.append(RetryError)
except ImportError:
    pass

# Standard network errors
RETRIABLE_EXCEPTIONS.extend([
    OSError,
    TimeoutError,
    ConnectionError
])

logger = logging.getLogger(__name__)

def with_retry(
    stop_attempts: int = 3,
    wait_min: int = 1,
    wait_max: int = 10
) -> Callable:
    """Decorator to retry functions on transient cloud errors.
    
    Uses exponential backoff with jitter.
    
    Args:
        stop_attempts: Max number of retries
        wait_min: Minimum wait time in seconds
        wait_max: Maximum wait time in seconds
    """
    return retry(
        stop=stop_after_attempt(stop_attempts),
        wait=wait_exponential(multiplier=1, min=wait_min, max=wait_max),
        retry=retry_if_exception_type(tuple(RETRIABLE_EXCEPTIONS)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True
    )
