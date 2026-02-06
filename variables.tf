
# Phase 0: Region & Environment Setup


variable "aws_region" {
  description = "The primary AWS region where the writer instance and primary VPC will reside."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "A naming prefix used to organize resources and costs (e.g., 'prod', 'lab', 'dev')."
  type        = string
  default     = "aurora-dr-lab"
}


# Phase 1: East VPC Networking


variable "vpc_cidr" {
  description = "The primary IPv4 address space for the East VPC. Must not overlap with the West CIDR."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Address space for the Bastion Host. Traffic here is routed through the IGW."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_1_cidr" {
  description = "Address space for the first database node in us-east-1 (AZ-A)."
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_subnet_2_cidr" {
  description = "Address space for the second database node in us-east-1 (AZ-B)."
  type        = string
  default     = "10.0.3.0/24"
}


# Phase 2: Security & Identity


variable "management_ip" {
  description = "The specific administrator IP (CIDR format) allowed to reach the Bastion. Use x.x.x.x/32 for a single IP."
  type        = string

  # VALIDATION: Prevents '0.0.0.0/0' mistakes that lead to security audit failures.
  validation {
    condition     = can(cidrnetmask(var.management_ip))
    error_message = "The management_ip must be a valid CIDR block (e.g., 1.2.3.4/32)."
  }
}

variable "ssh_key_name" {
  description = "The name of the pre-existing AWS Key Pair used for EC2 authentication."
  type        = string
  default     = "jenna"
}

# ==========================================
# Phase 3: Database Credentials
# ==========================================

variable "db_master_username" {
  description = "The administrator username for the PostgreSQL engine."
  type        = string
  default     = "marcellus"

  validation {
    condition     = length(var.db_master_username) >= 1 && length(var.db_master_username) <= 16
    error_message = "AWS Aurora usernames must be between 1 and 16 characters."
  }
}

variable "db_master_password" {
  description = "The master password for the DB. Stored as a 'sensitive' value to hide it from console output."
  type        = string
  sensitive   = true # Prevents the password from appearing in 'terraform apply' logs

  validation {
    condition     = length(var.db_master_password) >= 8
    error_message = "Database passwords must be at least 8 characters long for compliance."
  }
}

# ==========================================
# Phase 4: Secondary Region (West)
# ==========================================

variable "secondary_vpc_id" {
  description = "The ID of the VPC in us-west-1. Used for cross-region peering and security group associations."
  type        = string
}

variable "secondary_vpc_cidr" {
  description = "The address space of the West VPC. Used for routing table updates in the East."
  type        = string
}

variable "secondary_private_subnet_ids" {
  description = "A list of at least two subnet IDs in the DR region to satisfy Aurora High Availability requirements."
  type        = list(string)

  validation {
    condition     = length(var.secondary_private_subnet_ids) >= 2
    error_message = "Aurora requires at least 2 subnets in different Availability Zones for the DB Subnet Group."
  }
}

variable "secondary_private_route_table_id" {
  description = "The specific Route Table ID in us-west-1 that will host the return route to the East VPC."
  type        = string
}
