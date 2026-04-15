"""
Device Provisioning Helper Functions
"""

import os
import json
from typing import Optional, Dict, Any
from .types import (
    EdgeOpsConfig,
    DeviceProvisioningRequest,
    DeviceProvisioningResponse,
    CertificateAuth,
)
from .errors import EdgeOpsProvisioningError

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ProvisioningOptions:
    """Options for device provisioning"""

    def __init__(
        self,
        api_base_url: str,
        auth_token: Optional[str] = None,
        save_certificates: bool = False,
        certificate_dir: str = "./certs",
    ):
        self.api_base_url = api_base_url
        self.auth_token = auth_token
        self.save_certificates = save_certificates
        self.certificate_dir = certificate_dir


def provision_device(
    options: ProvisioningOptions, request: DeviceProvisioningRequest
) -> DeviceProvisioningResponse:
    """
    Provision a new device with EdgeOps Cloud

    Args:
        options: Provisioning options
        request: Device provisioning request

    Returns:
        Provisioning response with certificates and connection info
    """
    if not REQUESTS_AVAILABLE:
        raise ImportError("requests is required for provisioning. Install with: pip install requests")

    headers = {
        "Content-Type": "application/json",
    }
    if options.auth_token:
        headers["Authorization"] = f"Bearer {options.auth_token}"

    try:
        response = requests.post(
            f"{options.api_base_url}/api/devices/provision",
            json={
                "deviceName": request["device_name"],
                "deviceType": request["device_type"],
                "metadata": request.get("metadata"),
            },
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        provisioning = response.json()

        # Save certificates to files if requested
        if options.save_certificates:
            save_certificates(options.certificate_dir, provisioning)

        return provisioning
    except requests.exceptions.HTTPError as error:
        error_data = error.response.json() if error.response else {}
        raise EdgeOpsProvisioningError(
            f"Provisioning failed: {error_data.get('error', error)}", error_data
        ) from error
    except Exception as error:
        raise EdgeOpsProvisioningError(f"Provisioning failed: {error}") from error


def create_config_from_provisioning(
    provisioning: DeviceProvisioningResponse, api_base_url: str
) -> EdgeOpsConfig:
    """
    Create EdgeOpsConfig from provisioning response

    Args:
        provisioning: Provisioning response
        api_base_url: API base URL

    Returns:
        Ready-to-use EdgeOpsConfig
    """
    auth: CertificateAuth = {
        "type": "certificate",
        "certificate": provisioning["provisioning"]["certificatePem"],
        "private_key": provisioning["provisioning"]["privateKey"],
        "root_ca": provisioning["provisioning"]["rootCa"],
        "iot_endpoint": provisioning["provisioning"]["iotEndpoint"],
    }

    return EdgeOpsConfig(
        api_base_url=api_base_url,
        device_id=provisioning["provisioning"]["deviceId"],
        organization_id=extract_org_id_from_device_id(provisioning["provisioning"]["deviceId"]),
        auth=auth,
        mqtt={"enabled": True},
    )


def provision_and_create_config(
    options: ProvisioningOptions, request: DeviceProvisioningRequest
) -> EdgeOpsConfig:
    """
    Provision device and create ready-to-use config

    Args:
        options: Provisioning options
        request: Device provisioning request

    Returns:
        Ready-to-use EdgeOpsConfig
    """
    provisioning = provision_device(options, request)
    return create_config_from_provisioning(provisioning, options.api_base_url)


def save_certificates(cert_dir: str, provisioning: DeviceProvisioningResponse) -> None:
    """Save certificates to files"""
    # Create directory if it doesn't exist
    os.makedirs(cert_dir, exist_ok=True)

    instructions = provisioning["instructions"]["certificates"]

    # Save device certificate
    with open(os.path.join(cert_dir, instructions["device"]), "w") as f:
        f.write(provisioning["provisioning"]["certificatePem"])

    # Save private key
    with open(os.path.join(cert_dir, instructions["private"]), "w") as f:
        f.write(provisioning["provisioning"]["privateKey"])

    # Download and save root CA
    try:
        root_ca_url = provisioning["provisioning"]["rootCa"]
        if root_ca_url.startswith("http"):
            root_ca_response = requests.get(root_ca_url, timeout=30)
            root_ca_response.raise_for_status()
            with open(os.path.join(cert_dir, instructions["root"]), "w") as f:
                f.write(root_ca_response.text)
        else:
            # If it's already a certificate string, save it directly
            with open(os.path.join(cert_dir, instructions["root"]), "w") as f:
                f.write(root_ca_url)
    except Exception as error:
        # If download fails, log warning
        print(f"Warning: Failed to download root CA: {error}")
        # You might want to include a default root CA in the SDK


def extract_org_id_from_device_id(device_id: str) -> str:
    """Extract organization ID from device ID. Device ID format: orgId-deviceName"""
    parts = device_id.split("-")
    return parts[0] if parts else "default"


def get_device_status(
    options: ProvisioningOptions, device_id: str
) -> Dict[str, Any]:
    """
    Get device provisioning status

    Args:
        options: Provisioning options
        device_id: Device ID to check

    Returns:
        Device status and shadow
    """
    if not REQUESTS_AVAILABLE:
        raise ImportError("requests is required. Install with: pip install requests")

    headers = {}
    if options.auth_token:
        headers["Authorization"] = f"Bearer {options.auth_token}"

    try:
        response = requests.get(
            f"{options.api_base_url}/api/devices/provision",
            params={"deviceId": device_id},
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as error:
        error_data = error.response.json() if error.response else {}
        raise EdgeOpsProvisioningError(
            f"Failed to get device status: {error_data.get('error', error)}", error_data
        ) from error
    except Exception as error:
        raise EdgeOpsProvisioningError(f"Failed to get device status: {error}") from error
