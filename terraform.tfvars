# AWS Configuration
aws_region  = "us-east-1"
environment = "lab"

# Network Configuration
vpc_cidr              = "10.0.0.0/16"
private_subnet_1_cidr = "10.0.1.0/24"
private_subnet_2_cidr = "10.0.2.0/24"

db_master_password = "11Pgadmin"

db_subnet_group_name = "labdb-subnet-group"
db_security_group_id = "sg-0218368e534d5626e" # Use the ID from your previous output
kms_key_id           = "arn:aws:kms:us-east-1:123456789012:key/your-key-uuid"

secondary_db_subnet_group_name = "labdb-subnet-group-us-west-1"

secondary_db_security_group_id = "sg-0abc1234def567890"

secondary_kms_key_id = "arn:aws:kms:us-west-1:123456789012:key/abcd1234-5678-90ef-abcd-1234567890ef"

