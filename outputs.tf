# Returns the ARN of the created KMS key to be used for encryption verification or IAM policy scoping
output "kms_key_id" {
  value = aws_kms_key.aurora_kms.arn
}

# Provides the DNS hostname for the writer instance; use this for all application write operations (INSERT, UPDATE, DELETE)
output "primary_cluster_endpoint" {
  description = "The writer endpoint for the primary cluster in us-east-1"
  value       = aws_rds_cluster.primary_cluster.endpoint
}

# Provides a load-balanced DNS hostname that distributes read traffic across all available replicas in the primary region
output "primary_cluster_reader_endpoint" {
  description = "The reader endpoint for the primary cluster in us-east-1"
  value       = aws_rds_cluster.primary_cluster.reader_endpoint
}

# Provides the local DNS hostname for the secondary region; use this to enable low-latency reads for users in US-West
output "secondary_cluster_reader_endpoint" {
  description = "The reader endpoint for the secondary cluster in us-west-1"
  value       = aws_rds_cluster.secondary_cluster.reader_endpoint
}

# Identifies the parent Global Cluster container that coordinates replication between the East and West regions
output "global_cluster_id" {
  description = "The ID of the Aurora Global Cluster"
  value       = aws_rds_global_cluster.lab_db_global.id
}

