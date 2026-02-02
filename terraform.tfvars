# AWS Configuration
aws_region  = "us-east-1"
environment = "lab"

# Network Configuration
vpc_cidr              = "10.0.0.0/16"
private_subnet_1_cidr = "10.0.1.0/24"
private_subnet_2_cidr = "10.0.2.0/24"

# Database Credentials
db_master_password = "11Pgadmin"

# Secondary Region Configuration (us-west-1)
# Note: You only need these if you are referencing existing resources in the secondary region
secondary_db_subnet_group_name = "labdb-subnet-group-us-west-1"
secondary_db_security_group_id = "sg-0abc1234def567890"
