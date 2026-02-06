# --- Region & Environment ---
variable "aws_region" {
  description = "The primary region for resources (East)"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Name of the environment for tagging"
  type        = string
  default     = "aurora-dr-lab"
}

# --- Networking (East) ---
variable "vpc_cidr" {
  description = "CIDR block for the East VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet in East"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_1_cidr" {
  description = "CIDR block for the first private subnet in East"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_subnet_2_cidr" {
  description = "CIDR block for the second private subnet in East"
  type        = string
  default     = "10.0.3.0/24"
}

# --- Security & Access ---
# FIX: Added missing variable to clear "undeclared variable" validate error
variable "management_ip" {
  description = "The specific public IP address allowed to SSH into the bastion (e.g., 1.2.3.4/32)"
  type        = string

  validation {
    condition     = can(cidrnetmask(var.management_ip))
    error_message = "The management_ip must be a valid CIDR block (e.g., x.x.x.x/32)."
  }
}

variable "ssh_key_name" {
  description = "Name of the SSH key pair for EC2 instances"
  type        = string
  default     = "jenna"
}

# --- Database Credentials ---
variable "db_master_username" {
  description = "Master username for Aurora database"
  type        = string
  default     = "marcellus"

  validation {
    condition     = length(var.db_master_username) >= 1 && length(var.db_master_username) <= 16
    error_message = "Username must be between 1 and 16 characters."
  }
}

variable "db_master_password" {
  description = "Master password for Aurora database"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.db_master_password) >= 8
    error_message = "Password must be at least 8 characters long."
  }
}

# --- Secondary Region Variables (West) ---
variable "secondary_vpc_id" {
  description = "The existing VPC ID in us-west-1"
  type        = string
}

variable "secondary_vpc_cidr" {
  description = "The CIDR block of the West VPC"
  type        = string
}

variable "secondary_private_subnet_ids" {
  description = "List of private subnet IDs in us-west-1 for the DB Subnet Group"
  type        = list(string)

  validation {
    condition     = length(var.secondary_private_subnet_ids) >= 2
    error_message = "At least 2 subnet IDs are required for Aurora DB subnet group."
  }
}

variable "secondary_private_route_table_id" {
  description = "The Route Table ID in us-west-1 that needs the return route to East"
  type        = string
}
