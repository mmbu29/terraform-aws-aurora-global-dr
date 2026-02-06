# Architecting Disaster Recovery: Automated Provisioning of Encrypted Aurora Global Clusters
# Fully Patched for tfsec, DNF Repo Access, and Cross-Region Peering

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

# --- Providers ---
provider "aws" {
  region = var.aws_region
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}

# --- Data Sources ---
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --- Phase 1: East VPC Networking & Hardened Logging ---

resource "aws_vpc" "lab_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.environment}-vpc" }
}

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
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flow-logs-${var.environment}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.cw_logs_key.arn
}

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

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LogGroupLevelActions"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = aws_cloudwatch_log_group.flow_log_group.arn
      },
      {
        Sid    = "LogStreamLevelActions"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        # tfsec:ignore:aws-iam-no-policy-wildcards
        Resource = "${aws_cloudwatch_log_group.flow_log_group.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "lab_vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.lab_vpc.id
}

resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id
  tags   = { Name = "${var.environment}-igw" }
}

resource "aws_subnet" "public_subnet_one" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.environment}-public-subnet-one" }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id
  tags   = { Name = "${var.environment}-public-rt" }
}

resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab_igw.id
}

resource "aws_route_table_association" "public_subnet_assoc" {
  subnet_id      = aws_subnet.public_subnet_one.id
  route_table_id = aws_route_table.public_rt.id
}

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

resource "aws_db_subnet_group" "lab_db_subnet_group" {
  name       = "labdb-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
  tags       = { Name = "labdb-subnet-group" }
}

# --- Phase 2: Security Groups (Hardened) ---

resource "aws_security_group" "bastion_sg" {
  name                   = "web-bastion-sg"
  description            = "Allows SSH and required outbound for updates"
  vpc_id                 = aws_vpc.lab_vpc.id
  revoke_rules_on_delete = true # Merged from duplicate block

  ingress {
    description = "Allow SSH from trusted IP only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_ip]
  }

  # RESOLVES dnf timeout: Allow HTTPS outbound to Reach AWS Repository Mirrors
  egress {
    description = "Allow HTTPS for DNF package updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow DB traffic to VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.secondary_vpc_cidr]
  }

  tags = { Name = "web-bastion-sg" }
}

resource "aws_security_group" "db_sec_grp" {
  name        = "DBsecGRP-East"
  description = "Allow PostgreSQL from Bastion"
  vpc_id      = aws_vpc.lab_vpc.id

  ingress {
    description     = "PostgreSQL from Bastion SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }

  egress {
    description = "Restrict outbound to VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "DBsecGRP-East" }
}

resource "aws_security_group" "secondary_db_sg" {
  provider    = aws.us_west_1
  name        = "DBsecGRP-West"
  description = "Allow PostgreSQL from East Bastion via Peering"
  vpc_id      = var.secondary_vpc_id

  ingress {
    description = "PostgreSQL from East VPC via peering"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Restrict outbound to Secondary VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.secondary_vpc_cidr]
  }

  tags = { Name = "DBsecGRP-West" }
}

# --- Phase 3: Encryption and Global Database ---

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
      "kms:DescribeKey",
      "kms:CreateGrant"
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

resource "aws_kms_key" "primary_kms" {
  provider                = aws.us_east_1
  description             = "KMS key for Aurora Primary - us-east-1"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.aurora_kms_policy.json
}

resource "aws_kms_key" "secondary_kms" {
  provider                = aws.us_west_1
  description             = "KMS key for Aurora Secondary - us-west-1"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.aurora_kms_policy.json
}

resource "aws_rds_global_cluster" "lab_db_global" {
  global_cluster_identifier = "lab-db-cluster"
  engine                    = "aurora-postgresql"
  engine_version            = "15.8"
  storage_encrypted         = true
}

resource "aws_rds_cluster" "primary_cluster" {
  provider                        = aws.us_east_1
  cluster_identifier              = "lab-db-global-cluster-1"
  global_cluster_identifier       = aws_rds_global_cluster.lab_db_global.id
  engine                          = aws_rds_global_cluster.lab_db_global.engine
  engine_version                  = aws_rds_global_cluster.lab_db_global.engine_version
  master_username                 = var.db_master_username
  master_password                 = var.db_master_password
  database_name                   = "labdb"
  db_subnet_group_name            = aws_db_subnet_group.lab_db_subnet_group.name
  vpc_security_group_ids          = [aws_security_group.db_sec_grp.id]
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.primary_kms.arn
  skip_final_snapshot             = true
  backup_retention_period         = 7
  preferred_backup_window         = "03:00-04:00"
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

resource "aws_rds_cluster_instance" "primary_writer" {
  provider                        = aws.us_east_1
  identifier                      = "lab-db-two-us-east-1"
  cluster_identifier              = aws_rds_cluster.primary_cluster.id
  instance_class                  = "db.r5.large"
  engine                          = aws_rds_cluster.primary_cluster.engine
  engine_version                  = aws_rds_cluster.primary_cluster.engine_version
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.primary_kms.arn
}

resource "aws_db_subnet_group" "secondary_subnet_group" {
  provider   = aws.us_west_1
  name       = "labdb-subnet-group-us-west-1"
  subnet_ids = var.secondary_private_subnet_ids
  tags       = { Name = "labdb-subnet-group-west" }
}

resource "aws_rds_cluster" "secondary_cluster" {
  provider                  = aws.us_west_1
  cluster_identifier        = "lab-db-us-west-1"
  global_cluster_identifier = aws_rds_global_cluster.lab_db_global.id
  engine                    = aws_rds_global_cluster.lab_db_global.engine
  engine_version            = aws_rds_global_cluster.lab_db_global.engine_version
  db_subnet_group_name      = aws_db_subnet_group.secondary_subnet_group.name
  vpc_security_group_ids    = [aws_security_group.secondary_db_sg.id]
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.secondary_kms.arn
  skip_final_snapshot       = true
  backup_retention_period   = 7
  preferred_backup_window   = "03:00-04:00"
  depends_on                = [aws_rds_cluster_instance.primary_writer]
}

resource "aws_rds_cluster_instance" "secondary_reader" {
  provider                        = aws.us_west_1
  identifier                      = "lab-db-one-us-west-1"
  cluster_identifier              = aws_rds_cluster.secondary_cluster.id
  instance_class                  = "db.r5.large"
  engine                          = aws_rds_cluster.secondary_cluster.engine
  engine_version                  = aws_rds_cluster.secondary_cluster.engine_version
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.secondary_kms.arn
}

# --- Phase 4: Bastion Hardening & IAM ---

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

resource "aws_iam_instance_profile" "bastion_profile" {
  name = "bastion-instance-profile-${var.environment}"
  role = aws_iam_role.bastion_ssm_role.name
}

resource "aws_iam_role_policy" "bastion_rds_describe" {
  name = "bastion-rds-describe"
  role = aws_iam_role.bastion_ssm_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["rds:DescribeDBClusters", "rds:DescribeDBInstances"]
      Resource = [aws_rds_cluster.primary_cluster.arn, aws_rds_cluster.secondary_cluster.arn]
    }]
  })
}

resource "aws_instance" "web_bastion" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  key_name                    = var.ssh_key_name
  subnet_id                   = aws_subnet.public_subnet_one.id
  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.bastion_profile.name
  associate_public_ip_address = true

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

# --- Phase 5: VPC Peering and Cross-Region Routing ---

resource "aws_vpc_peering_connection" "east_to_west" {
  provider    = aws.us_east_1
  vpc_id      = aws_vpc.lab_vpc.id
  peer_vpc_id = var.secondary_vpc_id
  peer_region = "us-west-1"
  auto_accept = false
  tags        = { Name = "Cross-Region-Peering" }
}

resource "aws_vpc_peering_connection_accepter" "west_accepter" {
  provider                  = aws.us_west_1
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id
  auto_accept               = true
}

resource "aws_route" "east_to_west_route" {
  route_table_id            = aws_route_table.public_rt.id
  destination_cidr_block    = var.secondary_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id
}

resource "aws_route" "west_to_east_route" {
  provider                  = aws.us_west_1
  route_table_id            = var.secondary_private_route_table_id
  destination_cidr_block    = var.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id
}

resource "aws_vpc_peering_connection_options" "requester_options" {
  provider                  = aws.us_east_1
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id

  requester {
    allow_remote_vpc_dns_resolution = true
  }
}

resource "aws_vpc_peering_connection_options" "accepter_options" {
  provider                  = aws.us_west_1
  vpc_peering_connection_id = aws_vpc_peering_connection.east_to_west.id
  depends_on                = [aws_vpc_peering_connection_accepter.west_accepter]

  accepter {
    allow_remote_vpc_dns_resolution = true
  }
}
