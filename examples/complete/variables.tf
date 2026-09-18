variable "aws_region" {
  description = <<-EOT
    Region hosting the trail, log group, functions, and rules. The trail itself
    is multi-region regardless, so this only decides where the stack lives.
  EOT
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = <<-EOT
    Inbox for sensitive-call alerts and the hourly digest. AWS mails a
    confirmation link that must be clicked before any alert is delivered.

    Keep this in a tfvars file that is not committed.
  EOT
  type        = string
}

variable "tags" {
  description = "Tags applied to the stack."
  type        = map(string)
  default = {
    managed-by = "terraform"
    module     = "org-keywatch"
  }
}
