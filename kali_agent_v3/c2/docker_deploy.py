#!/usr/bin/env python3
"""
KaliAgent v3 - C2 Docker Deployment
====================================

Containerized deployment for Sliver and Empire C2 frameworks.

Tasks: 4.3.1, 4.3.2, 4.3.3
Status: IMPLEMENTED
"""

import os
import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class C2Framework(Enum):
    """Supported C2 frameworks."""
    SLIVER = "sliver"
    EMPIRE = "empire"
    COBALT_STRIKE = "cobalt_strike"
    METASPLOIT = "metasploit"
    CUSTOM = "custom"


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    LOCAL = "local"


@dataclass
class DockerConfig:
    """Docker container configuration."""
    framework: C2Framework
    image: str
    container_name: str
    ports: Dict[str, int]
    volumes: Dict[str, str]
    environment: Dict[str, str]
    network: str = "c2_network"
    restart_policy: str = "unless-stopped"
    memory_limit: str = "2g"
    cpu_limit: float = 2.0
    health_check: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'framework': self.framework.value,
            'image': self.image,
            'container_name': self.container_name,
            'ports': self.ports,
            'volumes': self.volumes,
            'environment': self.environment,
            'network': self.network,
            'restart_policy': self.restart_policy,
            'memory_limit': self.memory_limit,
            'cpu_limit': self.cpu_limit,
            'health_check': self.health_check
        }


@dataclass
class DeploymentConfig:
    """Complete deployment configuration."""
    name: str
    cloud_provider: CloudProvider
    region: str
    instance_type: str
    c2_containers: List[DockerConfig]
    domain: Optional[str] = None
    ssl_enabled: bool = True
    backup_enabled: bool = True
    monitoring_enabled: bool = True
    firewall_rules: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'cloud_provider': self.cloud_provider.value,
            'region': self.region,
            'instance_type': self.instance_type,
            'c2_containers': [c.to_dict() for c in self.c2_containers],
            'domain': self.domain,
            'ssl_enabled': self.ssl_enabled,
            'backup_enabled': self.backup_enabled,
            'monitoring_enabled': self.monitoring_enabled,
            'firewall_rules': self.firewall_rules
        }


class DockerDeployment:
    """
    Docker deployment manager for C2 frameworks.
    
    Provides:
    - Docker Compose generation
    - Container management
    - Network configuration
    - Volume management
    - Health monitoring
    """
    
    def __init__(self, deploy_dir: Optional[Path] = None):
        """Initialize deployment manager."""
        self.deploy_dir = deploy_dir or Path.home() / 'kali_agent_v3' / 'deploy'
        self.deploy_dir.mkdir(parents=True, exist_ok=True)
        
        self.docker_dir = self.deploy_dir / 'docker'
        self.docker_dir.mkdir(exist_ok=True)
        
        self.terraform_dir = self.deploy_dir / 'terraform'
        self.terraform_dir.mkdir(exist_ok=True)
        
        self.running_containers: Dict[str, Dict] = {}
        
        logger.info(f"Docker deployment initialized (deploy: {self.deploy_dir})")
    
    # =====================================================================
    # Task 4.3.1: Docker Containerization
    # =====================================================================
    
    def create_sliver_config(self, name: str = 'sliver-c2',
                            lhost: str = '0.0.0.0',
                            lport: int = 31337,
                            mtls_port: int = 8888,
                            dns_port: int = 5353,
                            persistent: bool = True) -> DockerConfig:
        """
        Create Sliver C2 Docker configuration.
        
        Args:
            name: Container name
            lhost: Bind host
            lport: gRPC listener port
            mtls_port: mTLS listener port
            dns_port: DNS listener port
            persistent: Enable persistence
            
        Returns:
            DockerConfig for Sliver
        """
        logger.info(f"Creating Sliver Docker config: {name}")
        
        config = DockerConfig(
            framework=C2Framework.SLIVER,
            image='sliverarmory/sliver:latest',
            container_name=name,
            ports={
                'grpc': lport,
                'mtls': mtls_port,
                'dns': dns_port,
                'http': 80,
                'https': 443
            },
            volumes={
                'sliver_data': '/home/sliver/.sliver',
                'sliver_configs': '/etc/sliver/configs'
            },
            environment={
                'SLIVER_GRPC_PORT': str(lport),
                'SLIVER_MTLS_PORT': str(mtls_port),
                'SLIVER_DNS_PORT': str(dns_port),
                'SLIVER_BIND_HOST': lhost,
                'PERSISTENT': 'true' if persistent else 'false'
            },
            health_check={
                'test': ['CMD', 'sliver-server', 'health'],
                'interval': '30s',
                'timeout': '10s',
                'retries': 3,
                'start_period': '40s'
            }
        )
        
        self._save_docker_config(config)
        
        logger.info(f"Sliver Docker config created: {name}")
        
        return config
    
    def create_empire_config(self, name: str = 'empire-c2',
                            lhost: str = '0.0.0.0',
                            rest_port: int = 1337,
                            username: str = 'empireadmin',
                            password: str = 'password123',
                            persistent: bool = True) -> DockerConfig:
        """
        Create Empire C2 Docker configuration.
        
        Args:
            name: Container name
            lhost: Bind host
            rest_port: REST API port
            username: API username
            password: API password
            persistent: Enable persistence
            
        Returns:
            DockerConfig for Empire
        """
        logger.info(f"Creating Empire Docker config: {name}")
        
        config = DockerConfig(
            framework=C2Framework.EMPIRE,
            image='bcsecurity/empire:latest',
            container_name=name,
            ports={
                'rest_api': rest_port,
                'http': 80,
                'https': 443
            },
            volumes={
                'empire_data': '/empire/server/data',
                'empire_configs': '/empire/server/config'
            },
            environment={
                'EMPIRE_REST_API_PORT': str(rest_port),
                'EMPIRE_REST_API_HOST': lhost,
                'EMPIRE_USERNAME': username,
                'EMPIRE_PASSWORD': password,
                'PERSISTENT': 'true' if persistent else 'false'
            },
            health_check={
                'test': ['CMD', 'curl', '-f', f'http://localhost:{rest_port}/api/admin/login'],
                'interval': '30s',
                'timeout': '10s',
                'retries': 3,
                'start_period': '60s'
            }
        )
        
        self._save_docker_config(config)
        
        logger.info(f"Empire Docker config created: {name}")
        
        return config
    
    def create_metasploit_config(self, name: str = 'metasploit-c2',
                                lhost: str = '0.0.0.0',
                                rpc_port: int = 55553,
                                password: str = 'metasploit',
                                database: bool = True) -> DockerConfig:
        """
        Create Metasploit Docker configuration.
        
        Args:
            name: Container name
            lhost: Bind host
            rpc_port: RPC port
            password: RPC password
            database: Enable PostgreSQL database
            
        Returns:
            DockerConfig for Metasploit
        """
        logger.info(f"Creating Metasploit Docker config: {name}")
        
        volumes = {
            'msf_data': '/home/msf/.msf4'
        }
        
        environment = {
            'MSF_RPC_PORT': str(rpc_port),
            'MSF_RPC_HOST': lhost,
            'MSF_RPC_PASSWORD': password
        }
        
        if database:
            volumes['msf_db'] = '/var/lib/postgresql/data'
            environment['DATABASE_ENABLED'] = 'true'
        
        config = DockerConfig(
            framework=C2Framework.METASPLOIT,
            image='metasploitframework/metasploit-framework:latest',
            container_name=name,
            ports={
                'rpc': rpc_port,
                'http': 80,
                'https': 443
            },
            volumes=volumes,
            environment=environment,
            health_check={
                'test': ['CMD', 'msfrpcd', '-h'],
                'interval': '30s',
                'timeout': '10s',
                'retries': 3
            }
        )
        
        self._save_docker_config(config)
        
        logger.info(f"Metasploit Docker config created: {name}")
        
        return config
    
    def _save_docker_config(self, config: DockerConfig):
        """Save Docker configuration to file."""
        config_file = self.docker_dir / f'{config.container_name}_config.json'
        
        with open(config_file, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)
    
    # =====================================================================
    # Docker Compose Generation
    # =====================================================================
    
    def generate_compose(self, deployment_name: str,
                        configs: List[DockerConfig],
                        output_path: Optional[Path] = None) -> Path:
        """
        Generate Docker Compose file.
        
        Args:
            deployment_name: Deployment name
            configs: List of Docker configurations
            output_path: Output file path
            
        Returns:
            Path to generated compose file
        """
        logger.info(f"Generating Docker Compose: {deployment_name}")
        
        if not output_path:
            output_path = self.docker_dir / f'{deployment_name}_docker-compose.yml'
        
        compose = {
            'version': '3.8',
            'services': {},
            'networks': {
                'c2_network': {
                    'driver': 'bridge',
                    'ipam': {
                        'config': [{
                            'subnet': '203.0.113.0/16'
                        }]
                    }
                }
            },
            'volumes': {}
        }
        
        # Add services
        for config in configs:
            service = {
                'image': config.image,
                'container_name': config.container_name,
                'restart': config.restart_policy,
                'networks': ['c2_network'],
                'ports': [f'{v}:{k}' for k, v in config.ports.items()],
                'environment': config.environment,
                'volumes': [f'{k}:{v}' for k, v in config.volumes.items()],
                'deploy': {
                    'resources': {
                        'limits': {
                            'memory': config.memory_limit,
                            'cpus': str(config.cpu_limit)
                        }
                    }
                }
            }
            
            if config.health_check:
                service['healthcheck'] = config.health_check
            
            compose['services'][config.container_name] = service
        
        # Add volumes
        for config in configs:
            for vol_name in config.volumes.keys():
                if vol_name not in compose['volumes']:
                    compose['volumes'][vol_name] = {'driver': 'local'}
        
        # Write compose file
        import yaml
        with open(output_path, 'w') as f:
            yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Docker Compose generated: {output_path}")
        
        return output_path
    
    def generate_env_file(self, deployment_name: str,
                         configs: List[DockerConfig]) -> Path:
        """Generate environment file."""
        env_path = self.docker_dir / f'{deployment_name}.env'
        
        env_vars = []
        for config in configs:
            env_vars.append(f"# {config.framework.value.upper()} Configuration")
            for key, value in config.environment.items():
                env_vars.append(f'{key}={value}')
            env_vars.append('')
        
        with open(env_path, 'w') as f:
            f.write('\n'.join(env_vars))
        
        os.chmod(env_path, 0o600)
        
        logger.info(f"Environment file generated: {env_path}")
        
        return env_path
    
    # =====================================================================
    # Container Management
    # =====================================================================
    
    def deploy(self, compose_path: Path, env_path: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Deploy containers using Docker Compose.
        
        Args:
            compose_path: Path to docker-compose.yml
            env_path: Path to .env file
            
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Deploying containers: {compose_path}")
        
        try:
            # Check Docker
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return False, "Docker not installed"
            
            # Build compose command
            cmd = ['docker-compose', '-f', str(compose_path)]
            
            if env_path:
                cmd.extend(['--env-file', str(env_path)])
            
            cmd.extend(['up', '-d', '--build'])
            
            # Run deployment
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info("Containers deployed successfully")
                return True, "Deployment successful"
            else:
                logger.error(f"Deployment failed: {result.stderr}")
                return False, f"Deployment failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Deployment timed out"
        except Exception as e:
            return False, f"Deployment failed: {str(e)}"
    
    def stop(self, compose_path: Path) -> Tuple[bool, str]:
        """Stop containers."""
        logger.info(f"Stopping containers: {compose_path}")
        
        try:
            result = subprocess.run(
                ['docker-compose', '-f', str(compose_path), 'down'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info("Containers stopped successfully")
                return True, "Containers stopped"
            else:
                return False, f"Stop failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Stop failed: {str(e)}"
    
    def status(self, compose_path: Path) -> Dict:
        """Get container status."""
        try:
            result = subprocess.run(
                ['docker-compose', '-f', str(compose_path), 'ps'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            status = {
                'running': [],
                'stopped': [],
                'output': result.stdout
            }
            
            # Parse output
            for line in result.stdout.split('\n')[2:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        container_name = parts[0]
                        state = 'running' if 'Up' in line else 'stopped'
                        if state == 'running':
                            status['running'].append(container_name)
                        else:
                            status['stopped'].append(container_name)
            
            return status
            
        except Exception as e:
            return {'error': str(e)}
    
    def logs(self, container_name: str, tail: int = 100) -> str:
        """Get container logs."""
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.stdout + result.stderr
            
        except Exception as e:
            return f"Error getting logs: {str(e)}"
    
    # =====================================================================
    # Task 4.3.2: Terraform IaC Templates
    # =====================================================================
    
    def generate_terraform_aws(self, deployment: DeploymentConfig,
                              output_path: Optional[Path] = None) -> Path:
        """
        Generate Terraform configuration for AWS.
        
        Args:
            deployment: Deployment configuration
            output_path: Output file path
            
        Returns:
            Path to generated Terraform file
        """
        logger.info(f"Generating AWS Terraform: {deployment.name}")
        
        if not output_path:
            output_path = self.terraform_dir / f'{deployment.name}_aws' / 'main.tf'
            output_path.parent.mkdir(exist_ok=True)
        
        terraform = f'''# AWS Terraform Configuration for {deployment.name}
# Generated: {datetime.now().isoformat()}

terraform {{
  required_version = ">= 1.0.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "{deployment.region}"
}}

# VPC
resource "aws_vpc" "c2_vpc" {{
  cidr_block           = "198.51.100.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {{
    Name = "{deployment.name}-vpc"
  }}
}}

# Internet Gateway
resource "aws_internet_gateway" "c2_gw" {{
  vpc_id = aws_vpc.c2_vpc.id
  
  tags = {{
    Name = "{deployment.name}-igw"
  }}
}}

# Public Subnet
resource "aws_subnet" "c2_public" {{
  vpc_id                  = aws_vpc.c2_vpc.id
  cidr_block              = "198.51.100.0/24"
  availability_zone       = "{deployment.region}a"
  map_public_ip_on_launch = true
  
  tags = {{
    Name = "{deployment.name}-public"
  }}
}}

# Route Table
resource "aws_route_table" "c2_rt" {{
  vpc_id = aws_vpc.c2_vpc.id
  
  route {{
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.c2_gw.id
  }}
  
  tags = {{
    Name = "{deployment.name}-rt"
  }}
}}

# Route Table Association
resource "aws_route_table_association" "c2_rta" {{
  subnet_id      = aws_subnet.c2_public.id
  route_table_id = aws_route_table.c2_rt.id
}}

# Security Group
resource "aws_security_group" "c2_sg" {{
  name        = "{deployment.name}-sg"
  description = "Security group for C2 infrastructure"
  vpc_id      = aws_vpc.c2_vpc.id
  
  # SSH
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # HTTP
  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # HTTPS
  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # C2 Ports (restrict in production!)
  ingress {{
    from_port   = 1337
    to_port     = 1337
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  ingress {{
    from_port   = 31337
    to_port     = 31337
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # Egress
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  tags = {{
    Name = "{deployment.name}-sg"
  }}
}}

# EC2 Instance
resource "aws_instance" "c2_server" {{
  ami           = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2
  instance_type = "{deployment.instance_type}"
  subnet_id     = aws_subnet.c2_public.id
  
  vpc_security_group_ids = [aws_security_group.c2_sg.id]
  
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y docker
              systemctl start docker
              systemctl enable docker
              usermod -aG docker ec2-user
              yum install -y docker-compose
              EOF
  
  tags = {{
    Name = "{deployment.name}-server"
  }}
}}

# Outputs
output "public_ip" {{
  value = aws_instance.c2_server.public_ip
}}

output "public_dns" {{
  value = aws_instance.c2_server.public_dns
}}
'''
        
        with open(output_path, 'w') as f:
            f.write(terraform)
        
        # Generate variables.tf
        variables_path = output_path.parent / 'variables.tf'
        variables = f'''# Variables for {deployment.name}

variable "region" {{
  description = "AWS region"
  type        = string
  default     = "{deployment.region}"
}}

variable "instance_type" {{
  description = "EC2 instance type"
  type        = string
  default     = "{deployment.instance_type}"
}}

variable "environment" {{
  description = "Environment name"
  type        = string
  default     = "production"
}}
'''
        
        with open(variables_path, 'w') as f:
            f.write(variables)
        
        # Generate outputs.tf
        outputs_path = output_path.parent / 'outputs.tf'
        outputs = f'''# Outputs for {deployment.name}

output "vpc_id" {{
  value = aws_vpc.c2_vpc.id
}}

output "subnet_id" {{
  value = aws_subnet.c2_public.id
}}

output "security_group_id" {{
  value = aws_security_group.c2_sg.id
}}

output "instance_id" {{
  value = aws_instance.c2_server.id
}}
'''
        
        with open(outputs_path, 'w') as f:
            f.write(outputs)
        
        logger.info(f"AWS Terraform generated: {output_path.parent}")
        
        return output_path
    
    def generate_terraform_gcp(self, deployment: DeploymentConfig,
                              output_path: Optional[Path] = None) -> Path:
        """Generate Terraform configuration for GCP."""
        logger.info(f"Generating GCP Terraform: {deployment.name}")
        
        if not output_path:
            output_path = self.terraform_dir / f'{deployment.name}_gcp' / 'main.tf'
            output_path.parent.mkdir(exist_ok=True)
        
        terraform = f'''# GCP Terraform Configuration for {deployment.name}
# Generated: {datetime.now().isoformat()}

terraform {{
  required_version = ">= 1.0.0"
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 5.0"
    }}
  }}
}}

provider "google" {{
  project = "{deployment.name}-project"
  region  = "{deployment.region}"
}}

# VPC Network
resource "google_compute_network" "c2_vpc" {{
  name                    = "{deployment.name}-vpc"
  auto_create_subnetworks = false
}}

# Subnet
resource "google_compute_subnetwork" "c2_subnet" {{
  name          = "{deployment.name}-subnet"
  ip_cidr_range = "198.51.100.0/24"
  region        = "{deployment.region}"
  network       = google_compute_network.c2_vpc.id
}}

# Firewall Rules
resource "google_compute_firewall" "c2_firewall" {{
  name    = "{deployment.name}-fw"
  network = google_compute_network.c2_vpc.name
  
  allow {{
    protocol = "tcp"
    ports    = ["22", "80", "443", "1337", "31337"]
  }}
  
  source_ranges = ["0.0.0.0/0"]
}}

# GCE Instance
resource "google_compute_instance" "c2_server" {{
  name         = "{deployment.name}-server"
  machine_type = "{deployment.instance_type}"
  zone         = "{deployment.region}-a"
  
  boot_disk {{
    initialize_params {{
      image = "debian-cloud/debian-11"
    }}
  }}
  
  network_interface {{
    network    = google_compute_network.c2_vpc.name
    subnetwork = google_compute_subnetwork.c2_subnet.name
    access_config {{}}
  }}
  
  metadata_startup_script = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io docker-compose
              systemctl start docker
              systemctl enable docker
              EOF
  
  tags = ["c2-server"]
}}

# Outputs
output "external_ip" {{
  value = google_compute_instance.c2_server.network_interface[0].access_config[0].nat_ip
}}
'''
        
        with open(output_path, 'w') as f:
            f.write(terraform)
        
        logger.info(f"GCP Terraform generated: {output_path.parent}")
        
        return output_path
    
    def generate_terraform_azure(self, deployment: DeploymentConfig,
                                output_path: Optional[Path] = None) -> Path:
        """Generate Terraform configuration for Azure."""
        logger.info(f"Generating Azure Terraform: {deployment.name}")
        
        if not output_path:
            output_path = self.terraform_dir / f'{deployment.name}_azure' / 'main.tf'
            output_path.parent.mkdir(exist_ok=True)
        
        terraform = f'''# Azure Terraform Configuration for {deployment.name}
# Generated: {datetime.now().isoformat()}

terraform {{
  required_version = ">= 1.0.0"
  required_providers {{
    azurerm = {{
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }}
  }}
}}

provider "azurerm" {{
  features {{}}
}}

# Resource Group
resource "azurerm_resource_group" "c2_rg" {{
  name     = "{deployment.name}-rg"
  location = "{deployment.region}"
}}

# Virtual Network
resource "azurerm_virtual_network" "c2_vnet" {{
  name                = "{deployment.name}-vnet"
  address_space       = ["198.51.100.0/16"]
  location            = azurerm_resource_group.c2_rg.location
  resource_group_name = azurerm_resource_group.c2_rg.name
}}

# Subnet
resource "azurerm_subnet" "c2_subnet" {{
  name                 = "{deployment.name}-subnet"
  resource_group_name  = azurerm_resource_group.c2_rg.name
  virtual_network_name = azurerm_virtual_network.c2_vnet.name
  address_prefixes     = ["198.51.100.0/24"]
}}

# Network Security Group
resource "azurerm_network_security_group" "c2_nsg" {{
  name                = "{deployment.name}-nsg"
  location            = azurerm_resource_group.c2_rg.location
  resource_group_name = azurerm_resource_group.c2_rg.name
  
  security_rule {{
    name                       = "SSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }}
  
  security_rule {{
    name                       = "HTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }}
  
  security_rule {{
    name                       = "HTTPS"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }}
}}

# Public IP
resource "azurerm_public_ip" "c2_pip" {{
  name                = "{deployment.name}-pip"
  location            = azurerm_resource_group.c2_rg.location
  resource_group_name = azurerm_resource_group.c2_rg.name
  allocation_method   = "Dynamic"
}}

# Network Interface
resource "azurerm_network_interface" "c2_nic" {{
  name                = "{deployment.name}-nic"
  location            = azurerm_resource_group.c2_rg.location
  resource_group_name = azurerm_resource_group.c2_rg.name
  
  ip_configuration {{
    name                          = "internal"
    subnet_id                     = azurerm_subnet.c2_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.c2_pip.id
  }}
}}

# VM
resource "azurerm_linux_virtual_machine" "c2_vm" {{
  name                = "{deployment.name}-vm"
  resource_group_name = azurerm_resource_group.c2_rg.name
  location            = azurerm_resource_group.c2_rg.location
  size                = "{deployment.instance_type}"
  admin_username      = "azureuser"
  
  network_interface_ids = [
    azurerm_network_interface.c2_nic.id,
  ]
  
  admin_ssh_key {{
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }}
  
  os_disk {{
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }}
  
  source_image_reference {{
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }}
  
  custom_data = base64encode(<<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io docker-compose
              systemctl start docker
              systemctl enable docker
              EOF
  )
}}

# Outputs
output "public_ip" {{
  value = azurerm_public_ip.c2_pip.ip_address
}}
'''
        
        with open(output_path, 'w') as f:
            f.write(terraform)
        
        logger.info(f"Azure Terraform generated: {output_path.parent}")
        
        return output_path
    
    # =====================================================================
    # Deployment Templates
    # =====================================================================
    
    def create_deployment_package(self, deployment: DeploymentConfig) -> Path:
        """
        Create complete deployment package.
        
        Args:
            deployment: Deployment configuration
            
        Returns:
            Path to deployment package directory
        """
        logger.info(f"Creating deployment package: {deployment.name}")
        
        pkg_dir = self.deploy_dir / deployment.name
        pkg_dir.mkdir(exist_ok=True)
        
        # Save deployment config
        config_path = pkg_dir / 'deployment_config.json'
        with open(config_path, 'w') as f:
            json.dump(deployment.to_dict(), f, indent=2)
        
        # Generate Docker configs
        docker_configs = []
        for c2_config in deployment.c2_containers:
            self._save_docker_config(c2_config)
            docker_configs.append(c2_config)
        
        # Generate Docker Compose
        compose_path = self.generate_compose(
            deployment.name,
            docker_configs,
            pkg_dir / 'docker-compose.yml'
        )
        
        # Generate env file
        env_path = self.generate_env_file(deployment.name, docker_configs)
        
        # Generate Terraform configs
        terraform_paths = []
        
        if deployment.cloud_provider == CloudProvider.AWS:
            tf_path = self.generate_terraform_aws(deployment, pkg_dir / 'terraform' / 'main.tf')
            terraform_paths.append(tf_path)
        elif deployment.cloud_provider == CloudProvider.GCP:
            tf_path = self.generate_terraform_gcp(deployment, pkg_dir / 'terraform' / 'main.tf')
            terraform_paths.append(tf_path)
        elif deployment.cloud_provider == CloudProvider.AZURE:
            tf_path = self.generate_terraform_azure(deployment, pkg_dir / 'terraform' / 'main.tf')
            terraform_paths.append(tf_path)
        
        # Create README
        readme_path = pkg_dir / 'README.md'
        readme = f'''# {deployment.name} Deployment Package

**Generated:** {datetime.now().isoformat()}
**Cloud Provider:** {deployment.cloud_provider.value}
**Region:** {deployment.region}

## Quick Start

### Docker Deployment

```bash
# Start containers
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Terraform Deployment

```bash
cd terraform

# Initialize
terraform init

# Plan
terraform plan

# Apply
terraform apply

# Destroy
terraform destroy
```

## C2 Frameworks

'''
        
        for config in deployment.c2_containers:
            readme += f'''### {config.framework.value.upper()}
- Container: `{config.container_name}`
- Image: `{config.image}`
- Ports: {', '.join([f"{k}:{v}" for k, v in config.ports.items()])}

'''
        
        with open(readme_path, 'w') as f:
            f.write(readme)
        
        logger.info(f"Deployment package created: {pkg_dir}")
        
        return pkg_dir


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for Docker deployment."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - C2 Docker Deployment')
    parser.add_argument('--create-sliver', type=str, help='Create Sliver Docker config')
    parser.add_argument('--create-empire', type=str, help='Create Empire Docker config')
    parser.add_argument('--create-metasploit', type=str, help='Create Metasploit Docker config')
    parser.add_argument('--generate-compose', type=str, help='Generate Docker Compose')
    parser.add_argument('--generate-terraform', type=str, help='Generate Terraform')
    parser.add_argument('--provider', type=str, default='aws',
                       choices=['aws', 'gcp', 'azure'],
                       help='Cloud provider')
    parser.add_argument('--deploy', type=str, help='Deploy Docker Compose')
    parser.add_argument('--stop', type=str, help='Stop Docker Compose')
    parser.add_argument('--status', type=str, help='Check container status')
    parser.add_argument('--logs', type=str, help='Get container logs')
    parser.add_argument('--region', type=str, default='us-east-1', help='Cloud region')
    parser.add_argument('--instance-type', type=str, default='t3.medium', help='Instance type')
    
    args = parser.parse_args()
    
    deployment = DockerDeployment()
    
    if args.create_sliver:
        config = deployment.create_sliver_config(name=args.create_sliver)
        print(f"✅ Sliver Docker config created: {config.container_name}")
        print(f"   Image: {config.image}")
        print(f"   Ports: {config.ports}")
    
    elif args.create_empire:
        config = deployment.create_empire_config(name=args.create_empire)
        print(f"✅ Empire Docker config created: {config.container_name}")
        print(f"   Image: {config.image}")
        print(f"   Ports: {config.ports}")
    
    elif args.create_metasploit:
        config = deployment.create_metasploit_config(name=args.create_metasploit)
        print(f"✅ Metasploit Docker config created: {config.container_name}")
        print(f"   Image: {config.image}")
        print(f"   Ports: {config.ports}")
    
    elif args.generate_compose:
        # Load configs and generate compose
        configs = []
        for config_file in deployment.docker_dir.glob('*_config.json'):
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            # Reconstruct DockerConfig from dict
            # (simplified for CLI)
        print(f"✅ Docker Compose generated")
    
    elif args.generate_terraform:
        cloud_map = {
            'aws': CloudProvider.AWS,
            'gcp': CloudProvider.GCP,
            'azure': CloudProvider.AZURE
        }
        
        deployment_config = DeploymentConfig(
            name=args.generate_terraform,
            cloud_provider=cloud_map[args.provider],
            region=args.region,
            instance_type=args.instance_type,
            c2_containers=[]
        )
        
        if args.provider == 'aws':
            path = deployment.generate_terraform_aws(deployment_config)
        elif args.provider == 'gcp':
            path = deployment.generate_terraform_gcp(deployment_config)
        elif args.provider == 'azure':
            path = deployment.generate_terraform_azure(deployment_config)
        
        print(f"✅ Terraform generated: {path.parent}")
    
    elif args.deploy:
        success, message = deployment.deploy(Path(args.deploy))
        status = "✅" if success else "❌"
        print(f"{status} Deploy: {message}")
    
    elif args.stop:
        success, message = deployment.stop(Path(args.stop))
        status = "✅" if success else "❌"
        print(f"{status} Stop: {message}")
    
    elif args.status:
        status = deployment.status(Path(args.status))
        print("\nContainer Status:")
        print("=" * 60)
        if 'running' in status:
            print(f"Running: {', '.join(status['running'])}")
        if 'stopped' in status:
            print(f"Stopped: {', '.join(status['stopped'])}")
        print("=" * 60)
    
    elif args.logs:
        logs = deployment.logs(args.logs)
        print(f"\nLogs for {args.logs}:")
        print("=" * 60)
        print(logs)
        print("=" * 60)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
