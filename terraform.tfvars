# Primary Region Config
aws_region         = "us-east-1"
environment        = "aurora-global-lab"
db_master_username = "marcellus"
db_master_password = "Pgadmin111A"
ssh_key_name       = "jenna"

# Networking - Primary (us-east-1)
vpc_cidr              = "10.0.0.0/16"
public_subnet_cidr    = "10.0.1.0/24"
private_subnet_1_cidr = "10.0.2.0/24"
private_subnet_2_cidr = "10.0.3.0/24"

# Security Access
# UPDATED: Using your verified public IP to resolve SSH timeouts and tfsec compliance
management_ip = "24.185.135.129/32"

# ============================================================================
# West Region Config (us-west-1) - UPDATED WITH LIVE IDs
# ============================================================================
secondary_vpc_id                 = "vpc-09b2ef2f048dea7d8"
secondary_vpc_cidr               = "172.31.0.0/16"
secondary_private_route_table_id = "rtb-07609a15948e4c5d7"

secondary_private_subnet_ids = [
  "subnet-0db788bd35aa16a02",
  "subnet-000b58aee2757c122"
]
