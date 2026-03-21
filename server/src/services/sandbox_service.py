# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Sandbox service layer for business logic.

This module contains the business logic for sandbox lifecycle management.
This module defines the abstract interface for sandbox services.
"""

from abc import ABC, abstractmethod
import re
import socket
from uuid import uuid4

from src.api.schema import (
    CreateSandboxRequest,
    CreateSandboxResponse,
    Endpoint,
    ListSandboxesRequest,
    ListSandboxesResponse,
    RenewSandboxExpirationRequest,
    RenewSandboxExpirationResponse,
    Sandbox,
)
from src.services.validators import ensure_valid_port


class SandboxService(ABC):
    """
    Abstract service interface for sandbox lifecycle operations.

    This class defines the interface for all sandbox service implementations.
    Implementations should handle creating, managing, and destroying sandboxes.
    """

    @staticmethod
    def generate_sandbox_id(prefix: str | None = None) -> str:
        """
        Generate a unique sandbox identifier.

        Returns:
            str: A RFC4122-compliant UUID4 string (with hyphens), or a readable
                DNS-label-safe prefix followed by a short random suffix.
        """
        readable_prefix = SandboxService._sanitize_sandbox_id_prefix(prefix)
        if readable_prefix:
            return f"{readable_prefix}-{uuid4().hex[:8]}"
        return str(uuid4())

    @staticmethod
    def _sanitize_sandbox_id_prefix(prefix: str | None) -> str:
        """
        Convert a human-readable prefix into a DNS-label-safe sandbox id prefix.

        The final sandbox id appends ``-<8hex>``, so the prefix itself is capped
        at 54 characters to keep the overall resource name within Kubernetes'
        63-character DNS label limit.
        """
        if prefix is None:
            return ""
        normalized = prefix.strip().lower()
        if not normalized:
            return ""
        normalized = re.sub(r"[^a-z0-9-]+", "-", normalized)
        normalized = re.sub(r"-{2,}", "-", normalized).strip("-")
        if not normalized:
            return ""
        normalized = normalized[:54].strip("-")
        return normalized

    @staticmethod
    def _resolve_bind_ip(family: int = socket.AF_INET) -> str:
        """
        Resolve the outward-facing IP for hosts binding to 0.0.0.0.

        Returns:
            str: Detected local IP address, or 127.0.0.1 as a safe fallback.
        """
        try:
            target = ("2001:4860:4860::8888", 80, 0, 0) if family == socket.AF_INET6 else ("8.8.8.8", 80)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect(target)
                ip = sock.getsockname()[0]
                if ip:
                    if family == socket.AF_INET or not ip.startswith("fe80"):
                        return ip
        except OSError:
            if family == socket.AF_INET6:
                return SandboxService._resolve_bind_ip(socket.AF_INET)

        try:
            family_name = socket.AF_INET6 if family == socket.AF_INET6 else socket.AF_INET
            hostname = socket.gethostname()
            infos = socket.getaddrinfo(hostname, None, family_name, socket.SOCK_DGRAM)
            if infos:
                addr = infos[0][4][0]
                if addr:
                    return addr
        except OSError:
            pass

        return "::1" if family == socket.AF_INET6 else "127.0.0.1"

    @staticmethod
    def validate_port(port: int) -> None:
        """
        Validate that the supplied port falls within the allowed range.

        Args:
            port: Port to validate

        Raises:
            ValueError: If port is outside 1-65535
        """
        ensure_valid_port(port)

    @abstractmethod
    def create_sandbox(self, request: CreateSandboxRequest) -> CreateSandboxResponse:
        """
        Create a new sandbox from a container image.

        Args:
            request: Sandbox creation request

        Returns:
            CreateSandboxResponse: Created sandbox information

        Raises:
            HTTPException: If sandbox creation fails
        """
        pass

    @abstractmethod
    def list_sandboxes(self, request: ListSandboxesRequest) -> ListSandboxesResponse:
        """
        List sandboxes with optional filtering and pagination.

        Args:
            request: List request with filters and pagination

        Returns:
            ListSandboxesResponse: Paginated list of sandboxes
        """
        pass

    @abstractmethod
    def get_sandbox(self, sandbox_id: str) -> Sandbox:
        """
        Fetch a sandbox by id.

        Args:
            sandbox_id: Unique sandbox identifier

        Returns:
            Sandbox: Complete sandbox information

        Raises:
            HTTPException: If sandbox not found
        """
        pass

    @abstractmethod
    def delete_sandbox(self, sandbox_id: str) -> None:
        """
        Delete a sandbox.

        Args:
            sandbox_id: Unique sandbox identifier

        Raises:
            HTTPException: If sandbox not found or deletion fails
        """
        pass

    @abstractmethod
    def pause_sandbox(self, sandbox_id: str) -> None:
        """
        Pause a running sandbox.

        Args:
            sandbox_id: Unique sandbox identifier

        Raises:
            HTTPException: If sandbox not found or cannot be paused
        """
        pass

    @abstractmethod
    def resume_sandbox(self, sandbox_id: str) -> None:
        """
        Resume a paused sandbox.

        Args:
            sandbox_id: Unique sandbox identifier

        Raises:
            HTTPException: If sandbox not found or cannot be resumed
        """
        pass

    @abstractmethod
    def renew_expiration(
        self,
        sandbox_id: str,
        request: RenewSandboxExpirationRequest,
    ) -> RenewSandboxExpirationResponse:
        """
        Renew sandbox expiration time.

        Args:
            sandbox_id: Unique sandbox identifier
            request: Renewal request with new expiration time

        Returns:
            RenewSandboxExpirationResponse: Updated expiration time

        Raises:
            HTTPException: If sandbox not found or renewal fails
        """
        pass

    @abstractmethod
    def get_endpoint(self, sandbox_id: str, port: int, resolve_internal: bool = False) -> Endpoint:
        """
        Get sandbox access endpoint.

        Args:
            sandbox_id: Unique sandbox identifier
            port: Port number where the service is listening inside the sandbox
            resolve_internal: If True, return the internal container IP (for proxy), ignoring router config.

        Returns:
            Endpoint: Public endpoint URL

        Raises:
            HTTPException: If sandbox not found or endpoint not available
        """
        pass
