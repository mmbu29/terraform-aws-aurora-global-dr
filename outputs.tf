# --- KMS Key Outputs ---
# These are used for auditing encryption and managing key rotations.

output "primary_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the KMS key used for Aurora encryption in us-east-1"
  value       = aws_kms_key.primary_kms.arn
}

output "primary_kms_key_id" {
  description = "The unique UUID of the KMS key in the primary region"
  value       = aws_kms_key.primary_kms.key_id
}

output "secondary_kms_key_arn" {
  description = "The ARN of the KMS key used for Aurora encryption in us-west-1 (DR region)"
  value       = aws_kms_key.secondary_kms.arn
}

output "secondary_kms_key_id" {
  description = "The unique UUID of the KMS key in the secondary region"
  value       = aws_kms_key.secondary_kms.key_id
}

# --- Global Cluster Outputs ---
# The Global Cluster links regional clusters for cross-region replication.

output "global_cluster_id" {
  description = "The logical identifier for the Aurora Global Database"
  value       = aws_rds_global_cluster.lab_db_global.id
}

output "global_cluster_arn" {
  description = "The ARN of the Global Cluster used for IAM policy scoping"
  value       = aws_rds_global_cluster.lab_db_global.arn
}

# --- Primary Cluster Outputs (us-east-1) ---
# Use the endpoint below for all application WRITE traffic.

output "primary_cluster_endpoint" {
  description = "The floating DNS writer endpoint for the primary region cluster"
  value       = aws_rds_cluster.primary_cluster.endpoint
}

output "primary_cluster_reader_endpoint" {
  description = "The read-only endpoint for load-balancing queries in us-east-1"
  value       = aws_rds_cluster.primary_cluster.reader_endpoint
}

output "primary_cluster_id" {
  description = "The regional cluster identifier for the primary database"
  value       = aws_rds_cluster.primary_cluster.id
}

output "primary_cluster_arn" {
  description = "The ARN of the primary cluster"
  value       = aws_rds_cluster.primary_cluster.arn
}

output "primary_instance_id" {
  description = "The identifier of the physical db.r5.large instance in us-east-1"
  value       = aws_rds_cluster_instance.primary_writer.id
}

# --- Secondary Cluster Outputs (us-west-1) ---
# Use these endpoints for Disaster Recovery testing and local read-scaling in the West.

output "secondary_cluster_endpoint" {
  description = "The cluster endpoint for the us-west-1 region (Promoted to writer during failover)"
  value       = aws_rds_cluster.secondary_cluster.endpoint
}

output "secondary_cluster_reader_endpoint" {
  description = "The reader endpoint used for local reads in the us-west-1 region"
  value       = aws_rds_cluster.secondary_cluster.reader_endpoint
}

output "secondary_cluster_id" {
  description = "The regional cluster identifier for the secondary (DR) database"
  value       = aws_rds_cluster.secondary_cluster.id
}

output "secondary_cluster_arn" {
  description = "The ARN of the secondary cluster"
  value       = aws_rds_cluster.secondary_cluster.arn
}

output "secondary_instance_id" {
  description = "The identifier of the physical db.r5.large instance in us-west-1"
  value       = aws_rds_cluster_instance.secondary_reader.id
}

# --- Bastion Host Outputs ---
# These outputs provide the "keys to the kingdom" for administrative access.

output "bastion_public_ip" {
  description = "The public IP of the Bastion jump box (Inbound restricted to management_ip)"
  value       = aws_instance.web_bastion.public_ip
}

output "bastion_instance_id" {
  description = "The Instance ID required for starting AWS Systems Manager (SSM) sessions"
  value       = aws_instance.web_bastion.id
}

output "bastion_ssh_command" {
  description = "The exact CLI command to SSH into the Bastion host"
  value       = "ssh -i ${var.ssh_key_name}.pem ec2-user@${aws_instance.web_bastion.public_ip}"
}

output "bastion_ssm_command" {
  description = "The CLI command to start a secure SSM session without needing SSH keys"
  value       = "aws ssm start-session --target ${aws_instance.web_bastion.id} --region ${var.aws_region}"
}

# --- Network Outputs ---
# Verifies successful multi-region network bridging.

output "east_vpc_id" {
  description = "The ID of the primary VPC in us-east-1"
  value       = aws_vpc.lab_vpc.id
}

output "east_vpc_cidr" {
  description = "The IPv4 address space allocated to the East VPC"
  value       = aws_vpc.lab_vpc.cidr_block
}

output "vpc_peering_connection_id" {
  description = "The ID of the VPC Peering connection linking East to West"
  value       = aws_vpc_peering_connection.east_to_west.id
}

# --- Security Group Outputs ---
# Used for troubleshooting connection issues or adding new rules.

output "bastion_security_group_id" {
  description = "The SG ID governing access to the Bastion host"
  value       = aws_security_group.bastion_sg.id
}

output "primary_db_security_group_id" {
  description = "The SG ID governing access to the Primary database"
  value       = aws_security_group.db_sec_grp.id
}

output "secondary_db_security_group_id" {
  description = "The SG ID governing access to the Secondary database"
  value       = aws_security_group.secondary_db_sg.id
}

# --- Connection Information ---
# Note: These commands work only when executed from within the Bastion host.

output "primary_db_connection_command" {
  description = "Command to connect to the Primary Writer via the psql client"
  value       = "psql -h ${aws_rds_cluster.primary_cluster.endpoint} -U ${var.db_master_username} -d labdb"
  sensitive   = false
}

output "secondary_db_connection_command" {
  description = "Command to connect to the Secondary Reader via the psql client"
  value       = "psql -h ${aws_rds_cluster.secondary_cluster.reader_endpoint} -U ${var.db_master_username} -d labdb"
  sensitive   = false
}

# --- Helpful Next Steps ---
# A dynamic "README" generated in the terminal after every successful terraform apply.

output "next_steps" {
  description = "Post-deployment instructions for testing and verification"
  value       = <<-EOT
  
  ======================================================================
  Aurora Global Database Deployment Complete!
  ======================================================================
  
  1. CONNECT TO BASTION:
     ${aws_instance.web_bastion.public_ip != "" ? "SSH: ssh -i ${var.ssh_key_name}.pem ec2-user@${aws_instance.web_bastion.public_ip}" : ""}
     SSM: aws ssm start-session --target ${aws_instance.web_bastion.id} --region ${var.aws_region}
  
  2. TEST PRIMARY DATABASE (From Bastion):
     psql -h ${aws_rds_cluster.primary_cluster.endpoint} -U ${var.db_master_username} -d labdb
  
  3. TEST SECONDARY DATABASE (From Bastion):
     psql -h ${aws_rds_cluster.secondary_cluster.reader_endpoint} -U ${var.db_master_username} -d labdb
  
  4. VALIDATE REPLICATION (Run on Primary):
     SELECT * FROM pg_stat_replication;
  
  5. VERIFY CROSS-REGION PEERING:
     Use 'ping' or 'nc' from the Bastion to test connectivity to the West VPC CIDR.

  Global Cluster ID: ${aws_rds_global_cluster.lab_db_global.id}
  Status: All resources successfully provisioned with AES-256 encryption.
  ======================================================================
  EOT
}
