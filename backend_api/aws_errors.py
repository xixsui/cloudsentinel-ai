"""Actionable AWS errors without returning SDK messages or credential material."""
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound, EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError


def explain(exc):
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError, ProfileNotFound)):
        return "AWS credentials/profile not found on the backend. Configure the selected WSL profile or enter Access Keys in Settings."
    if isinstance(exc, (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError)):
        return "AWS endpoint could not be reached. Check the region, network, proxy and DNS, then retry."
    code = exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else ""
    if code in {"ExpiredToken", "ExpiredTokenException", "RequestExpired"}:
        return "AWS credentials have expired. Renew the temporary credentials or sign in to the profile again, then reconnect."
    if code in {"InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch", "InvalidSignatureException", "AuthFailure"}:
        return "AWS rejected the credentials. Check the Access Key and Secret pair; temporary credentials also require the matching Session Token."
    if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
        return "AWS denied this read operation. Ask the account administrator to review IAM, resource policies and organization restrictions for this service."
    if code in {"Throttling", "ThrottlingException", "RequestLimitExceeded"}:
        return "AWS request limit reached. Wait briefly before retrying."
    return "AWS request failed. Check credentials, region and network connectivity, then reconnect."
