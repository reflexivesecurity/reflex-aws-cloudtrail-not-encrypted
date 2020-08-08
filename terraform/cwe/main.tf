module "cwe" {
  source      = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe?ref=v2.0.0"
  name        = "CloudtrailNotEncrypted"
  description = "Detect if a Cloudtrail trail does not encrypt log files. "

  event_pattern = <<PATTERN
{
  "source": [
    "aws.cloudtrail"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "CreateTrail",
      "UpdateTrail"
    ]
  }
}
PATTERN
}
