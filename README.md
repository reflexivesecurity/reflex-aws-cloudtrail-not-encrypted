# reflex-aws-cloudtrail-not-encrypted
A Reflex rule to detect if a CloudTrail trail does not encrypt log files.

To learn more about CloudTrail trail encryption, see [the AWS Documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html).

## Getting Started
To get started using Reflex, check out [the Reflex Documentation](https://docs.cloudmitigator.com/).

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
rules:
  aws:
    - cloudtrail-not-encrypted:
        version: latest
```

or add it directly to your Terraform:  
```
module "cloudtrail-not-encrypted" {
  source            = "git::https://github.com/cloudmitigator/reflex-aws-cloudtrail-not-encrypted.git?ref=latest"
  sns_topic_arn     = module.central-sns-topic.arn
  reflex_kms_key_id = module.reflex-kms-key.key_id
}
```

Note: The `sns_topic_arn` and `reflex_kms_key_id` example values shown here assume you generated resources with `reflex build`. If you are using the Terraform on its own you need to provide your own valid values.

## Configuration
This rule has no configuration options.

## Contributing
If you are interested in contributing, please review [our contribution guide](https://docs.cloudmitigator.com/about/contributing.html).

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-cloudtrail-not-encrypted/blob/master/LICENSE) 
