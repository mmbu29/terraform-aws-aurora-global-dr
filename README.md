# AWS Aurora Global Database: Disaster Recovery Lab

This project demonstrates a multi-region, high-availability database architecture using **Amazon Aurora PostgreSQL** and **Terraform**. It is designed to survive a full AWS regional outage with minimal data loss.
Architecture
- **Primary Region (us-east-1):** Master cluster handling all Read/Write traffic.
- **Secondary Region (us-west-1):** Global Read Replica for low-latency local reads and fast failover.
- **Security:** Encrypted at rest using **AWS KMS** and isolated within private VPC subnets.

Key Features
* **Global Replication:** Sub-second data synchronization between East and West coasts.
* **Automated Failover:** Includes a PowerShell script (`Failover.ps1`) to promote the secondary region to Primary in under 2 minutes.

Getting Started
1. Clone this repo.
2. Run `terraform init` to download providers.
3. Run `terraform apply` to deploy the global infrastructure.
4. Use the `Failover.ps1` script in the `/scripts` folder to test a regional outage.

Performance (TPS)
Initial tests using `pgbench` show:
- **Primary Write TPS:** ~1,200 (db.t3.medium)
- **Replication Lag:** < 200ms
