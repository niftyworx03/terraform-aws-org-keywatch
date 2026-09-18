module "keywatch" {
  source = "../.."

  alert_email = var.alert_email

  # Also passed explicitly rather than relying on default_tags alone, so the
  # tags land on resources even if a caller drops the provider block above.
  tags = var.tags

  # Every account in the organization, every principal. Narrow this with
  # monitored_access_key_ids only if you have keys you specifically care about
  # and want the rest of the organization to stay quiet.
  monitored_access_key_ids = []

  # The digest mails hourly whether or not anything happened, which is what
  # turns a silent inbox into a signal instead of an assumption.
  heartbeat_schedule    = "cron(0 * * * ? *)"
  heartbeat_always_send = true

  # log_retention_days bounds how far back the digest can look, so it has to
  # stay comfortably above heartbeat_lookback_hours or the digest silently
  # queries a window that no longer exists.
  trail_retention_days      = 90
  log_retention_days        = 30
  lambda_log_retention_days = 14

  # GuardDuty is the only component that can bill, and organization-wide it
  # bills per member account rather than once. Left off so this example is
  # free to run. Turn all three on together if you want behavioural detection
  # in addition to the named-event list.
  create_guardduty_detector     = false
  enable_guardduty_alerts       = false
  guardduty_auto_enable_members = false
}
