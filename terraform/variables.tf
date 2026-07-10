variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  type        = string
  description = "AWS account ID for CaucellCloud"
}

variable "admin_user_arns" {
  type        = list(string)
  description = "IAM user ARNs allowed to assume KmsKeyAdmin role"
}

variable "phi_bucket_names" {
  type        = list(string)
  description = "List of research bucket names (without the research- prefix)"
  default     = ["research-phi-primary"]
}

variable "object_lock_retention_days" {
  type        = number
  description = "Default Object Lock Governance mode retention in days"
  default     = 2190 # ~6 years
}

variable "audit_retention_days" {
  type        = number
  description = "Audit log Object Lock Compliance mode retention in days"
  default     = 2555 # ~7 years
}

variable "alert_email" {
  type        = string
  description = "Email address for security alert notifications"
}

variable "cloudtrail_regions" {
  type        = string
  description = "Comma-separated AWS regions for CloudTrail partition projection"
  default     = "us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,eu-west-1,eu-west-2,eu-west-3,eu-central-1,eu-north-1,ap-south-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,ap-northeast-2,sa-east-1"
}

variable "cloudtrail_start_date" {
  type        = string
  description = "Partition projection start date for CloudTrail logs (yyyy/MM/dd)"
  default     = "2026/05/01"
}

variable "synology_start_date" {
  type        = string
  description = "Partition projection start date for Synology NAS access logs (yyyy-MM-dd)"
  default     = "2026-06-01"
}

variable "quicksight_admin_username" {
  type        = string
  description = "QuickSight admin username for dataset and data source permissions"
}

variable "nas_backup_ia_transition_days" {
  type        = number
  description = "Days before NAS backup objects transition Standard -> Standard-IA"
  default     = 30
}

variable "nas_backup_glacier_transition_days" {
  type        = number
  description = "Days before NAS backup objects transition Standard-IA -> Glacier Flexible Retrieval"
  default     = 90
}

variable "nas_backup_deep_archive_transition_days" {
  type        = number
  description = "Days before NAS backup objects transition Glacier -> Glacier Deep Archive"
  default     = 180
}

variable "nas_cloudsync_noncurrent_expiration_days" {
  type        = number
  description = "Days before a superseded (noncurrent) Cloud Sync object version is permanently expired"
  default     = 180
}
