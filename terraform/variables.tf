variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "misconfig-detector"
}

variable "region" {
  description = "AWS region to deploy into. Root console sign-in events arrive in us-east-1 only."
  type        = string
  default     = "eu-west-2"
}

variable "alert_email" {
  description = "E-mail address subscribed to the findings topic. Leave empty to subscribe later."
  type        = string
  default     = ""
}

variable "create_trail" {
  description = "Create a multi-region CloudTrail trail. Set to false if the account already has one (for example an organisation trail)."
  type        = bool
  default     = true
}

variable "min_severity" {
  description = "Lowest severity that is sent to SNS: LOW, MEDIUM, HIGH or CRITICAL."
  type        = string
  default     = "MEDIUM"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.min_severity)
    error_message = "min_severity must be LOW, MEDIUM, HIGH or CRITICAL."
  }
}

variable "auto_remediate" {
  description = "Undo open security group rules and restore S3 Block Public Access automatically."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Days to keep Lambda logs."
  type        = number
  default     = 30
}
