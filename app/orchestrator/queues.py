"""RQ queue names shared by producers, workers and the service status page."""

ALERTS = "ai-alerts"
# Alert analysis runs apart from notifications; manual clicks are taken first.
ALERT_MANUAL = "ai-alert-manual"
ALERT_ANALYSIS = "ai-alert-analysis"
QUESTIONS = "ai-questions"
DIAGNOSTICS = "ai-diagnostics"
ALL = (ALERTS, ALERT_MANUAL, ALERT_ANALYSIS, QUESTIONS, DIAGNOSTICS)
