# Architecting Disaster Recovery: Automated Provisioning of Encrypted Aurora Global Clusters
# Purpose: Multi-region PostgreSQL 15.8 with hardened logging, encryption, and peering.

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Remote state ensures team collaboration and state locking
  backend "s3" {
    bucket  = "max-terraform-state-kinesis-project"
    key     = "aurora-lab/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

# --- Providers ---
# Primary provider for general resources
provider "aws" {
  region = var.aws_region
}

# Explicit provider for the Primary Region (East)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# Explicit provider for the DR Region (West)
provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}

# --- Data Sources ---
# Fetches available AZs to ensure high availability across different data centers
data "aws_availability_zones" "available" {
  state = "available"
}

# Retrieves the AWS Account ID for use in IAM and KMS policies
data "aws_caller_identity" "current" {}

# Fetches the latest Amazon Linux 2023 AMI for a secure, up-to-date Bastion host
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# --- Phase 1: East VPC Networking & Hardened Logging ---

# The primary networking boundary for the production environment
resource "aws_vpc" "lab_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.environment}-vpc" }
}

# Customer Managed Key (CMK) to ensure logs are encrypted at rest (Compliance requirement)
resource "aws_kms_key" "cw_logs_key" {
  description             = "KMS key for CloudWatch Log Group encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:GenerateDataKey*"]
        Resource  = "*"
      }
    ]
  })
}

# Secure container for VPC Flow Logs to monitor all network traffic
resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flow-logs-${var.environment}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.cw_logs_key.arn
}

# IAM Role allowing VPC service to write logs to CloudWatch
resource "aws_iam_role" "flow_log_role" {
  name = "vpc-flow-log-role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

# Permission set for Flow Logs (Limited to specific Log Group for security)
resource "aws_iam_role_policy" "flow_log_policy" {
  name = "vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_log_group.arn}:*"
    }]
  })
}

# Captures IP traffic flow for the VPC (Audit trail for security assessments)
resource "aws_flow_log" "lab_vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.lab_vpc.id
}

# Gateway providing Internet access for the Bastion host
resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id
  tags   = { Name = "${var.environment}-igw" }
}

# Public subnet for the Bastion; MapPublicIP is false by default for security
resource "aws_subnet" "public_subnet_one" {
  vpc_id            = aws_vpc.lab_vpc.id
  cidr_block        = var.public_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${var.environment}-public-subnet-one" }
}

# Routing table for Public traffic
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id
  tags   = { Name = "${var.environment}-public-rt" }
}

# Default route out to the internet via IGW
resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab_igw.id
}

# Associations link subnets to specific routing logic
resource "aws_route_table_association" "public_subnet_assoc" {
  subnet_id      = aws_subnet.public_subnet_one.id
  route_table_id = aws_route_table.public_rt.id
}

# Isolated private subnets across 2 AZs to host the Aurora instances
resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.lab_vpc.id
  cidr_block        = var.private_subnet_1_cidr
  availability_zone = data.aws_availability_zones.available.names[1]
  tags              = { Name = "${var.environment}-private-subnet-1" }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.lab_vpc.id
  cidr_block        = var.private_subnet_2_cidr
  availability_zone = data.aws_availability_zones.available.names[2]
  tags              = { Name = "${var.environment}-private-subnet-2" }
}

# Groups private subnets for the RDS engine
resource "aws_db_subnet_group" "lab_db_subnet_group" {
  name       = "labdb-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
}

# --- Phase 2: Security Groups (Hardened) ---

# Bastion SG: Allows inbound SSH and outbound 443 for DNF/Package updates
resource "aws_security_group" "bastion_sg" {
  name   = "web-bastion-sg"
  vpc_id = aws_vpc.lab_vpc.id

  ingress {
    description = "SSH from Management IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_ip]
  }

  egress {
    description = "HTTPS for OS Updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "PostgreSQL to DB subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.secondary_vpc_cidr]
  }
}

# Database SG: Implements Zero Trust by only allowing traffic from the Bastion SG
resource "aws_security_group" "db_sec_grp" {
  name   = "DBsecGRP-East"
  vpc_id = aws_vpc.lab_vpc.id

  ingress {
    description     = "PostgreSQL from Bastion"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
}

# West Region Security Group: Supports cross-region traffic via VPC Peering
resource "aws_security_group" "secondary_db_sg" {
  provider = aws.us_west_1
  name     = "DBsecGRP-West"
  vpc_id   = var.secondary_vpc_id

  ingress {
    description = "PostgreSQL from East VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

# --- Phase 3: Encryption and Global Database ---

# KMS Keys for cross-region encryption (Ensures data is unreadable if stolen)
resource "aws_kms_key" "primary_kms" {
  provider            = aws.us_east_1
  description         = "KMS key for Aurora Primary"
  enable_key_rotation = true
}

resource "aws_kms_key" "secondary_kms" {
  provider            = aws.us_west_1
  description         = "KMS key for Aurora Secondary"
  enable_key_rotation = true
}

# Logic to link regional clusters into one Global Entity
resource "aws_rds_global_cluster" "lab_db_global" {
  global_cluster_identifier = "lab-db-cluster"
  engine                    = "aurora-postgresql"
  engine_version            = "15.8"
  storage_encrypted         = true
}

# Primary Cluster (The Writer) in East
resource "aws_rds_cluster" "primary_cluster" {
  provider                        = aws.us_east_1
  cluster_identifier              = "lab-db-global-cluster-1"
  global_cluster_identifier       = aws_rds_global_cluster.lab_db_global.id
  engine                          = aws_rds_global_cluster.lab_db_global.engine
  engine_version                  = aws_rds_global_cluster.lab_db_global.engine_version
  master_username                 = var.db_master_username
  master_password                 = var.db_master_password
  db_subnet_group_name            = aws_db_subnet_group.lab_db_subnet_group.name
  vpc_security_group_ids          = [aws_security_group.db_sec_grp.id]
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.primary_kms.arn
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

# Individual DB instance for the Primary Cluster
resource "aws_rds_cluster_instance" "primary_writer" {
  provider                     = aws.us_east_1
  identifier                   = "lab-db-two-us-east-1"
  cluster_identifier           = aws_rds_cluster.primary_cluster.id
  instance_class               = "db.r5.large"
  engine                       = aws_rds_cluster.primary_cluster.engine
  performance_insights_enabled = true
}

# Secondary Cluster (The Reader/Failover) in West
resource "aws_rds_cluster" "secondary_cluster" {
  provider                  = aws.us_west_1
  cluster_identifier        = "lab-db-us-west-1"
  global_cluster_identifier = aws_rds_global_cluster.lab_db_global.id
  engine                    = aws_rds_global_cluster.lab_db_global.engine
  engine_version            = aws_rds_global_cluster.lab_db_global.engine_version
  vpc_security_group_ids    = [aws_security_group.secondary_db_sg.id]
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.secondary_kms.arn
  # Depends_on ensures Primary is ready before West tries to replicate
  depends_on = [aws_rds_cluster_instance.primary_writer]
}

# --- Phase 4: Bastion Hardening & IAM ---

# IAM Role for System Manager (SSM) access—eliminates need for open port 22 in prod
resource "aws_iam_role" "bastion_ssm_role" {
  name = "bastion-ssm-role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# Assigns the IAM role to the Bastion EC2 instance
resource "aws_iam_instance_profile" "bastion_profile" {
  name = "bastion-instance-profile-${var.environment}"
  role = aws_iam_role.bastion_ssm_role.name
}

# The Jump Box for database administration and replication testing
resource "aws_instance" "web_bastion" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  key_name                    = var.ssh_key_name
  subnet_id                   = aws_subnet.public_subnet_one.id
  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.bastion_profile.name
  associate_public_ip_address = true

  # IMDSv2 requirement for session security
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

# --- Phase 5: VPC Peering and Cross-Region Routing ---

# Establishes the private network bridge between East and West
resource "aws_vpc_peering_connection" "east_to_west" {
  provider    = aws.us_east_1
  vpc_id      = aws_vpc.lab_vpc.id
  peer_vpc_id = var.secondary_vpc_id
  peer_region = "us-west-1"
  auto_accept = false
}

# Logic for the West region to "shake hands" with the East VPC
resource "aws_vpc_peering_connection_accepter" "west_accepter" {
  provider                  = aws.us_west_1
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id
  auto_accept               = true
}

# Routing logic to ensure DB traffic knows to cross the peering bridge
resource "aws_route" "east_to_west_route" {
  route_table_id            = aws_route_table.public_rt.id
  destination_cidr_block    = var.secondary_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id
}
