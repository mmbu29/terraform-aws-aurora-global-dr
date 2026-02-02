
# --- AWS Configuration ---
# Defines the primary geographical location where the regional AWS resources will be provisioned
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

# Sets a naming prefix to distinguish between different stages like 'lab', 'dev', or 'prod'
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

# Specifies the IP address range for the Virtual Private Cloud (VPC) network
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# Defines the IP range for the first private subnet, typically used for database high availability
variable "private_subnet_1_cidr" {
  description = "CIDR block for private subnet 1"
  type        = string
  default     = "10.0.1.0/24"
}

# Defines the IP range for the second private subnet to ensure cross-AZ redundancy
variable "private_subnet_2_cidr" {
  description = "CIDR block for private subnet 2"
  type        = string
  default     = "10.0.2.0/24"
}

# Defines the IP range for the second private subnet to ensure cross-AZ redundancy
variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.3.0/24"
}

# Sets the administrative login name for the Aurora PostgreSQL engine
variable "db_master_username" {
  description = "Master username for the Aurora PostgreSQL cluster"
  type        = string
  default     = "marcellus"
}

# Sets the sensitive administrative password; marked as sensitive to prevent logging in the console
variable "db_master_password" {
  description = "Master password for Aurora database"
  type        = string
  sensitive   = true
}

# --- Secondary Region Configuration (us-west-1) ---
# Specifies the subnet group name within the us-west-1 network for the replica cluster
variable "secondary_db_subnet_group_name" {
  description = "DB subnet group name for the secondary Aurora cluster"
  type        = string
}

# References the specific security group protecting the database in the us-west-1 region
variable "secondary_db_security_group_id" {
  description = "Security group ID for the secondary Aurora cluster"
  type        = string
}

# References the first private subnet ID in the secondary region (us-west-1)
variable "secondary_private_subnet_1_id" {
  description = "Private subnet 1 ID for the secondary Aurora cluster"
  type        = string
}

# References the second private subnet ID in the secondary region (us-west-1)
variable "secondary_private_subnet_2_id" {
  description = "Private subnet 2 ID for the secondary Aurora cluster"
  type        = string
}
