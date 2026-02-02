# Output for the Primary Region KMS Key
output "primary_kms_key_arn" {
  description = "The ARN of the KMS key in the primary region (us-east-1)"
  value       = aws_kms_key.primary_kms.arn
}

# Output for the Secondary Region KMS Key
output "secondary_kms_key_arn" {
  description = "The ARN of the KMS key in the secondary region (us-west-1)"
  value       = aws_kms_key.secondary_kms.arn
}

# Output for the Global Cluster ID
output "global_cluster_id" {
  description = "The ID of the Aurora Global Cluster"
  value       = aws_rds_global_cluster.lab_db_global.id
}

# Output for the Primary Cluster Endpoint
output "primary_cluster_endpoint" {
  description = "The writer endpoint for the primary cluster"
  value       = aws_rds_cluster.primary_cluster.endpoint
}
