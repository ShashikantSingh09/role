variable "gd_finding_publishing_frequency" {
  description = "A value that specifies how frequently updated findings are exported"
  default     = "FIFTEEN_MINUTES"
}

variable "gd_finding_bucket_name" {
  description = "S3 bucket name for GuardDuty findings"
  type        = string
  default     = ""
}

variable "kms_alias" {
  description = "KMS alias to create if enable_kms=true"
  type        = string
  default     = "guarduty-key"
}

variable "aws_regions" {
  type = list(string)
  default = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-south-1",
    "ca-central-1",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "me-south-1",
    "sa-east-1"
  ]
}

variable "auto_enable_organization_members" {
  description = "Whether to auto-enable members (NONE, NEW, ALL)"
  type        = string
  default     = "ALL"
}

variable "dataops_member_account_id" {
  description = "Account ID for the DataOps GuardDuty member whose S3_DATA_EVENTS feature is managed"
  type        = string
  default     = "533454354590"
}

variable "s3_data_events_feature_status" {
  description = "Desired status for S3_DATA_EVENTS feature for the DataOps account (ENABLED or DISABLED)"
  type        = string
  default     = "DISABLED"
}