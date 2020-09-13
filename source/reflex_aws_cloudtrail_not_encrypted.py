""" Module for CloudtrailNotEncrypted """

import json
import os

import boto3
from reflex_core import AWSRule, subscription_confirmation


class CloudtrailNotEncrypted(AWSRule):
    """ Detect if a Cloudtrail trail does not encrypt log files. """

    client = boto3.client("cloudtrail")

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.trail_name = event["detail"]["requestParameters"]["name"]

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """

        response = self.client.describe_trails(
            trailNameList=[
                self.trail_name
            ]
        )
        if "KmsKeyId" in response['trailList'][0].keys():
            return bool(response['trailList'][0]["KmsKeyId"])
        return False

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The trail named {self.trail_name} does not have encryption " \
               f"enabled. "


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    if subscription_confirmation.is_subscription_confirmation(event):
        subscription_confirmation.confirm_subscription(event)
        return
    rule = CloudtrailNotEncrypted(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
