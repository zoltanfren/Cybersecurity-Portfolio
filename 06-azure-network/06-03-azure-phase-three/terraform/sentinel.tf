# Enable Microsoft Sentinel on the existing Log Analytics workspace
# No additional standing cost — billed only on data ingestion beyond 5 GB/month free tier
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "lab" {
  workspace_id = var.law_workspace_id
}

# Detection rule 1 — Multiple failed SSH login attempts
# Triggers when 5 or more auth failures occur on the same host within 5 minutes
# Data source: Syslog (auth facility) — already ingested via AMA
resource "azurerm_sentinel_alert_rule_scheduled" "failed_ssh" {
  name                       = "failed-ssh-logins"
  log_analytics_workspace_id = var.law_workspace_id
  display_name               = "Multiple Failed SSH Login Attempts"
  severity                   = "Medium"
  enabled                    = true

  query = <<-KQL
    Syslog
    | where Facility == "auth"
    | where SyslogMessage contains "Failed password"
        or SyslogMessage contains "Invalid user"
    | summarize FailedAttempts = count() by Computer, bin(TimeGenerated, 5m)
    | where FailedAttempts >= 5
  KQL

  query_frequency = "PT5M"   # Run every 5 minutes
  query_period    = "PT5M"   # Look back 5 minutes

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.lab]
}

# Detection rule 2 — NVA forwarded traffic spike
# Triggers when NVA forwards 100+ packets in 5 minutes — potential lateral movement
# Data source: Syslog from vm-nva-01 with NVA-FORWARD iptables prefix
resource "azurerm_sentinel_alert_rule_scheduled" "nva_traffic_spike" {
  name                       = "nva-traffic-spike"
  log_analytics_workspace_id = var.law_workspace_id
  display_name               = "NVA Forwarded Traffic Spike"
  severity                   = "Low"
  enabled                    = true

  query = <<-KQL
    Syslog
    | where Computer == "vm-nva-01"
    | where SyslogMessage contains "NVA-FORWARD"
    | summarize PacketCount = count() by bin(TimeGenerated, 5m)
    | where PacketCount >= 100
  KQL

  query_frequency = "PT5M"
  query_period    = "PT5M"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.lab]
}