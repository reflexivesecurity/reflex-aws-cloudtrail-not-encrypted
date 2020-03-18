module "reflex_aws_cloudtrail_not_encrypted" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda"
  rule_name        = "CloudtrailNotEncrypted"
  rule_description = "Detect if a Cloudtrail trail does not encrypt log files. "

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

  function_name   = "CloudtrailNotEncrypted"
  source_code_dir = "${path.module}/source"
  handler         = "reflex_aws_cloudtrail_not_encrypted.lambda_handler"
  lambda_runtime  = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn,
    
  }
  custom_lambda_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudtrail:DescribeTrails"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF



  queue_name    = "CloudtrailNotEncrypted"
  delay_seconds = 0

  target_id = "CloudtrailNotEncrypted"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}