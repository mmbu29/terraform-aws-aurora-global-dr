# --- KMS Key Outputs ---
output "primary_kms_key_arn" {
  description = "The ARN of the KMS key in the primary region (us-east-1)"
  value       = aws_kms_key.primary_kms.arn
}

output "primary_kms_key_id" {
  description = "The ID of the KMS key in the primary region"
  value       = aws_kms_key.primary_kms.key_id
}

output "secondary_kms_key_arn" {
  description = "The ARN of the KMS key in the secondary region (us-west-1)"
  value       = aws_kms_key.secondary_kms.arn
}

output "secondary_kms_key_id" {
  description = "The ID of the KMS key in the secondary region"
  value       = aws_kms_key.secondary_kms.key_id
}

# --- Global Cluster Outputs ---
output "global_cluster_id" {
  description = "The ID of the Aurora Global Cluster"
  value       = aws_rds_global_cluster.lab_db_global.id
}

output "global_cluster_arn" {
  description = "The ARN of the Aurora Global Cluster"
  value       = aws_rds_global_cluster.lab_db_global.arn
}

# --- Primary Cluster Outputs (us-east-1) ---
output "primary_cluster_endpoint" {
  description = "The writer endpoint for the primary cluster"
  value       = aws_rds_cluster.primary_cluster.endpoint
}

output "primary_cluster_reader_endpoint" {
  description = "The reader endpoint for the primary cluster"
  value       = aws_rds_cluster.primary_cluster.reader_endpoint
}

output "primary_cluster_id" {
  description = "The ID of the primary Aurora cluster"
  value       = aws_rds_cluster.primary_cluster.id
}

output "primary_cluster_arn" {
  description = "The ARN of the primary Aurora cluster"
  value       = aws_rds_cluster.primary_cluster.arn
}

output "primary_instance_id" {
  description = "The instance ID of the primary writer"
  value       = aws_rds_cluster_instance.primary_writer.id
}

# --- Secondary Cluster Outputs (us-west-1) ---
output "secondary_cluster_endpoint" {
  description = "The endpoint for the secondary cluster"
  value       = aws_rds_cluster.secondary_cluster.endpoint
}

output "secondary_cluster_reader_endpoint" {
  description = "The reader endpoint for the secondary cluster"
  value       = aws_rds_cluster.secondary_cluster.reader_endpoint
}

output "secondary_cluster_id" {
  description = "The ID of the secondary Aurora cluster"
  value       = aws_rds_cluster.secondary_cluster.id
}

output "secondary_cluster_arn" {
  description = "The ARN of the secondary Aurora cluster"
  value       = aws_rds_cluster.secondary_cluster.arn
}

output "secondary_instance_id" {
  description = "The instance ID of the secondary reader"
  value       = aws_rds_cluster_instance.secondary_reader.id
}

# --- Bastion Host Outputs ---
output "bastion_public_ip" {
  description = "The public IP address of the bastion host"
  value       = aws_instance.web_bastion.public_ip
}

output "bastion_instance_id" {
  description = "The Instance ID for SSM sessions"
  value       = aws_instance.web_bastion.id
}

output "bastion_ssh_command" {
  description = "SSH command to connect to the bastion host"
  value       = "ssh -i ${var.ssh_key_name}.pem ec2-user@${aws_instance.web_bastion.public_ip}"
}

output "bastion_ssm_command" {
  description = "AWS SSM command to connect to the bastion host"
  value       = "aws ssm start-session --target ${aws_instance.web_bastion.id} --region ${var.aws_region}"
}

# --- Network Outputs ---
output "east_vpc_id" {
  description = "The VPC ID in us-east-1"
  value       = aws_vpc.lab_vpc.id
}

output "east_vpc_cidr" {
  description = "The CIDR block of the East VPC"
  value       = aws_vpc.lab_vpc.cidr_block
}

output "vpc_peering_connection_id" {
  description = "The ID of the VPC peering connection"
  value       = aws_vpc_peering_connection.east_to_west.id
}

# --- Security Group Outputs ---
output "bastion_security_group_id" {
  description = "The security group ID for the bastion host"
  value       = aws_security_group.bastion_sg.id
}

output "primary_db_security_group_id" {
  description = "The security group ID for the primary database"
  value       = aws_security_group.db_sec_grp.id
}

output "secondary_db_security_group_id" {
  description = "The security group ID for the secondary database"
  value       = aws_security_group.secondary_db_sg.id
}

# --- Connection Information ---
output "primary_db_connection_command" {
  description = "PostgreSQL connection command for the primary database (from bastion)"
  value       = "psql -h ${aws_rds_cluster.primary_cluster.endpoint} -U ${var.db_master_username} -d labdb"
  sensitive   = false
}

output "secondary_db_connection_command" {
  description = "PostgreSQL connection command for the secondary database (from bastion)"
  value       = "psql -h ${aws_rds_cluster.secondary_cluster.reader_endpoint} -U ${var.db_master_username} -d labdb"
  sensitive   = false
}

# --- Helpful Next Steps ---
output "next_steps" {
  description = "Next steps after deployment"
  value       = <<-EOT
  
  ========================================
  Aurora Global Database Deployment Complete!
  ========================================
  
  1. Connect to Bastion:
     ${aws_instance.web_bastion.public_ip != "" ? "SSH: ssh -i ${var.ssh_key_name}.pem ec2-user@${aws_instance.web_bastion.public_ip}" : ""}
     SSM: aws ssm start-session --target ${aws_instance.web_bastion.id} --region ${var.aws_region}
  
  2. Test Primary Database (from bastion):
     psql -h ${aws_rds_cluster.primary_cluster.endpoint} -U ${var.db_master_username} -d labdb
  
  3. Test Secondary Database (from bastion):
     psql -h ${aws_rds_cluster.secondary_cluster.reader_endpoint} -U ${var.db_master_username} -d labdb
  
  4. Check Replication Status:
     SELECT * FROM pg_stat_replication;
  
  5. Run Failover Test Script:
     ./aurora_failover_test.sh
  
  Global Cluster ID: ${aws_rds_global_cluster.lab_db_global.id}
  Primary Region: us-east-1
  Secondary Region: us-west-1
  
  ========================================
  EOT
}
