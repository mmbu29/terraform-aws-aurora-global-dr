# Architecting Disaster Recovery: Automated Provisioning of Encrypted Aurora Global Clusters across US-East and US-West
# # Configures the Terraform settings, including the required AWS provider and S3 remote state backend
terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket  = "max-terraform-state-kinesis-project"
    key     = "aurora-lab/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

# Sets the default AWS provider for the primary infrastructure region
provider "aws" {
  region = var.aws_region
}

# Configures the provider alias for the US East (N. Virginia) region
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# If you are adding the secondary region, you need this too
provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}

# Data source to get available AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Gets your AWS Account ID automatically
data "aws_caller_identity" "current" {}

# --- Phase 1: VPC and Networking Prerequisites ---
# VPC
resource "aws_vpc" "lab_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.environment}-vpc"
  }
}

# Provisions an Internet Gateway to allow the public subnet to communicate with the outside world
resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id
  tags = {
    Name = "${var.environment}-igw"
  }
}

# Creates a public subnet intended for bastion hosts or load balancers, though restricted from auto-assigning public IPs
resource "aws_subnet" "public_subnet_one" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-public-subnet-one"
  }
}

# Establishes a route table to manage traffic flow for public-facing resources
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id
  tags = {
    Name = "${var.environment}-public-rt"
  }
}

# Route to Internet Gateway
resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab_igw.id
}

# Associate Public Subnet with Route Table
resource "aws_route_table_association" "public_subnet_assoc" {
  subnet_id      = aws_subnet.public_subnet_one.id
  route_table_id = aws_route_table.public_rt.id
}

# Defines private subnet to host database instances in a secure, isolated zone
# Private Subnet 1
resource "aws_subnet" "private_subnet_1" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = var.private_subnet_1_cidr
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.environment}-private-subnet-1"
  }
}

# Private Subnet 2
resource "aws_subnet" "private_subnet_2" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = var.private_subnet_2_cidr
  availability_zone       = data.aws_availability_zones.available.names[2]
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.environment}-private-subnet-2"
  }
}

# Establishes a private route table for resources that do not require direct internet access
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.lab_vpc.id
  tags = {
    Name = "${var.environment}-private-rt"
  }
}

# Associates the first private subnet with the internal-only route table
resource "aws_route_table_association" "private_subnet_1_assoc" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

# Associates the second private subnet with the internal-only route table
resource "aws_route_table_association" "private_subnet_2_assoc" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

# DB Subnet Group for Aurora
resource "aws_db_subnet_group" "lab_db_subnet_group" {
  name        = "labdb-subnet-group"
  description = "Aurora DB Subnet Group spanning multiple AZs"
  subnet_ids = [
    aws_subnet.private_subnet_1.id,
    aws_subnet.private_subnet_2.id
  ]
  tags = {
    Name = "labdb-subnet-group"
  }
}

# Centralized KMS Policy Document
data "aws_iam_policy_document" "aurora_kms_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow RDS and CloudWatch to use the key"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    principals {
      type = "Service"
      identifiers = [
        "rds.amazonaws.com",
        "logs.us-east-1.amazonaws.com",
        "logs.us-west-1.amazonaws.com"
      ]
    }
  }
}

# Provisions a Customer Managed Key (CMK) for Primary Region
resource "aws_kms_key" "primary_kms" {
  provider                = aws.us_east_1
  description             = "KMS key for Aurora Primary - us-east-1"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.aurora_kms_policy.json
}

# Provisions a dedicated KMS Customer Managed Key for Secondary Region
resource "aws_kms_key" "secondary_kms" {
  provider                = aws.us_west_1
  description             = "KMS key for Aurora Secondary - us-west-1"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.aurora_kms_policy.json
}

# Provisions a CloudWatch Log Group to serve as the destination for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_logs" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 14
  kms_key_id        = aws_kms_key.primary_kms.arn
}

# Defines an IAM Role that allows the VPC Flow Logs service to assume permissions to write to CloudWatch
resource "aws_iam_role" "vpc_flow_log_role" {
  name = "vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

# Attaches an inline policy to the IAM role to grant specific logging permissions to CloudWatch
resource "aws_iam_role_policy" "vpc_flow_log_policy" {
  name = "vpc-flow-log-policy"
  role = aws_iam_role.vpc_flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      Resource = aws_cloudwatch_log_group.vpc_logs.arn
    }]
  })
}

# Enables the Flow Logs feature on the VPC to monitor all accepted and rejected IP traffic
resource "aws_flow_log" "vpc_flow_log" {
  log_destination      = aws_cloudwatch_log_group.vpc_logs.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.lab_vpc.id
  log_destination_type = "cloud-watch-logs"
  iam_role_arn         = aws_iam_role.vpc_flow_log_role.arn
}


# 9. DB Security Group (DBsecGRP) - NEW RESOURCE
resource "aws_security_group" "db_sec_grp" {
  name        = "DBsecGRP"
  description = "Security Group for Aurora, allowing PostgreSQL access (5432) from within the VPC"
  vpc_id      = aws_vpc.lab_vpc.id

  # Ingress rule: Allow PostgreSQL port 5432 from the entire VPC CIDR
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "PostgreSQL access from VPC"
  }

  # Egress rule: Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow outbound traffic only within VPC"
  }

  tags = {
    Name = "DBsecGRP"
  }
}

# 10. Aurora Cluster Parameter Group - NEW RESOURCE
resource "aws_rds_cluster_parameter_group" "lab_clu_param_grp" {
  name        = "lab-clu-param-grp-aupg-15"
  family      = "aurora-postgresql15" # Defines the engine and version (Aurora PostgreSQL 15)
  description = "Custom Cluster Parameter Group for Aurora PostgreSQL 15"

  tags = {
    Name = "lab-clu-param-grp-aupg-15"
  }
}

# 11. Aurora DB Instance Parameter Group - NEW RESOURCE
resource "aws_db_parameter_group" "lab_db_param_grp" {
  name        = "lab-db-param-grp-aupg-15"
  family      = "aurora-postgresql15" # Must match the cluster family
  description = "Custom DB Instance Parameter Group for Aurora PostgreSQL 15"

  tags = {
    Name = "lab-db-param-grp-aupg-15"
  }
}

# Creates the top-level Global Cluster container that manages cross-region replication logic
resource "aws_rds_global_cluster" "lab_db_global" {
  global_cluster_identifier = "lab-db-cluster"
  engine                    = "aurora-postgresql"
  engine_version            = "15.8"
  storage_encrypted         = true
}

# Provisions the Primary Aurora Cluster in US-East-1 which acts as the main Read/Write source
resource "aws_rds_cluster" "primary_cluster" {
  provider                  = aws.us_east_1
  cluster_identifier        = "lab-db-global-cluster-1"
  global_cluster_identifier = aws_rds_global_cluster.lab_db_global.id
  engine                    = aws_rds_global_cluster.lab_db_global.engine
  engine_version            = aws_rds_global_cluster.lab_db_global.engine_version

  master_username = var.db_master_username
  master_password = var.db_master_password
  database_name   = "labdb"

  db_subnet_group_name   = aws_db_subnet_group.lab_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sec_grp.id]

  storage_encrypted = true
  kms_key_id        = aws_kms_key.primary_kms.arn # Points to your us-east-1 KMS Key

  backup_retention_period = 7
  skip_final_snapshot     = true
}

# Provisions the Writer Instance within the primary cluster to execute database queries
resource "aws_rds_cluster_instance" "primary_writer" {
  provider           = aws.us_east_1
  identifier         = "lab-db-two-us-east-1"
  cluster_identifier = aws_rds_cluster.primary_cluster.id

  instance_class                  = "db.r5.large"
  engine                          = aws_rds_cluster.primary_cluster.engine
  engine_version                  = aws_rds_cluster.primary_cluster.engine_version
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.primary_kms.arn
  publicly_accessible             = false
}

# This creates the missing subnet group in us-west-1
resource "aws_db_subnet_group" "secondary_subnet_group" {
  provider   = aws.secondary # Crucial: tells Terraform to talk to us-west-1
  name       = "labdb-subnet-group-us-west-1"
  subnet_ids = [aws_subnet.secondary_private_1.id, aws_subnet.secondary_private_2.id]

  tags = {
    Name = "labdb-subnet-group-us-west-1"
  }
}

# Provisions the Secondary Aurora Cluster in US-West-1 to serve as a high-speed Read Replica and Disaster Recovery target
resource "aws_rds_cluster" "secondary_cluster" {
  provider                  = aws.us_west_1
  cluster_identifier        = "lab-db-us-west-1"
  global_cluster_identifier = aws_rds_global_cluster.lab_db_global.id
  engine                    = aws_rds_global_cluster.lab_db_global.engine
  engine_version            = aws_rds_global_cluster.lab_db_global.engine_version

  # FIX: Change this from the variable to the actual resource name
  db_subnet_group_name = aws_db_subnet_group.secondary_subnet_group.name

  vpc_security_group_ids = [var.secondary_db_security_group_id]

  storage_encrypted       = true
  kms_key_id              = aws_kms_key.secondary_kms.arn
  backup_retention_period = 7

  skip_final_snapshot = true

  # Crucial: Cluster creation depends on the primary writer AND the secondary subnet group
  depends_on = [
    aws_rds_cluster_instance.primary_writer,
    aws_db_subnet_group.secondary_subnet_group
  ]
}

# Provisions a Reader Instance in the secondary region to handle local read traffic and provide redundancy
resource "aws_rds_cluster_instance" "secondary_reader" {
  provider           = aws.us_west_1
  identifier         = "lab-db-one-us-west-1"
  cluster_identifier = aws_rds_cluster.secondary_cluster.id
  instance_class     = "db.r5.large"
  engine             = aws_rds_cluster.secondary_cluster.engine
  engine_version     = aws_rds_cluster.secondary_cluster.engine_version

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.secondary_kms.arn
  publicly_accessible             = false
}

# Fully isolated VPC with Flow Logs for security auditing
# Multi-layer encryption using AWS KMS (Storage and Performance Insights)
# Aurora PostgreSQL 15.8 Global Cluster with cross-region replication for < 1-second latency reads in the secondary region.
# Secure access via tightly scoped Security Groups allowing only necessary traffic
# Automated failover capabilities and a 7-day backup retention policy
