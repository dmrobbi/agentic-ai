"""Infrastructure module for deployment and service management."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List
from enum import Enum

class ServiceStatus(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

@dataclass
class Service:
    service_id: str
    name: str
    status: ServiceStatus = ServiceStatus.UNKNOWN
    environment: Environment = Environment.DEVELOPMENT
    version: str = ""
    health: float = 1.0
    endpoint: str = ""
    last_check: datetime = field(default_factory=datetime.now)

@dataclass
class Deployment:
    deployment_id: str
    service_name: str
    version: str
    environment: Environment = Environment.STAGING
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)

class InfrastructureManager:
    """Manage infrastructure, services, and deployments."""

    def __init__(self):
        self.services: List[Service] = []
        self.deployments: List[Deployment] = []

    def register_service(self, name: str, environment: str = "development",
                         version: str = "0.1.0", endpoint: str = "") -> Service:
        service_id = f"SVC-{len(self.services)+1:04d}"
        service = Service(
            service_id=service_id, name=name,
            environment=Environment(environment),
            version=version, endpoint=endpoint,
            status=ServiceStatus.RUNNING,
        )
        self.services.append(service)
        return service

    def deploy(self, service_name: str, version: str, environment: str = "staging") -> Deployment:
        deployment_id = f"DEP-{len(self.deployments)+1:04d}"
        deployment = Deployment(
            deployment_id=deployment_id,
            service_name=service_name,
            version=version,
            environment=Environment(environment),
            status="deploying",
        )
        self.deployments.append(deployment)
        return deployment

    def check_health(self, service_name: str = "") -> Dict[str, Any]:
        for svc in self.services:
            if svc.name == service_name:
                return {"service": service_name, "status": svc.status.value, "health": svc.health}
        return {"service": service_name, "status": "unknown", "health": 0.0}

    def get_all_services(self, environment: str = "") -> List[Service]:
        if environment:
            env = Environment(environment)
            return [s for s in self.services if s.environment == env]
        return self.services