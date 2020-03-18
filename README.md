# reflex-aws-cloudtrail-not-encrypted
Detect if a Cloudtrail trail does not encrypt log files . 

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
rules:
  - reflex-aws-cloudtrail-not-encrypted:
      email: "example@example.com"
```

or add it directly to your Terraform:  
```
...

module "reflex-aws-cloudtrail-not-encrypted" {
  source           = "github.com/cloudmitigator/reflex-aws-cloudtrail-not-encrypted"
  email            = "example@example.com"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-cloudtrail-not-encrypted/blob/master/LICENSE) 