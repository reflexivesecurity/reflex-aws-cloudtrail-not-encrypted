""" Module for ReflexAwsCloudtrailNotEncrypted """

import json
import os

import boto3
from reflex_core import AWSRule


class ReflexAwsCloudtrailNotEncrypted(AWSRule):
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
        return bool("KmsKeyId" in response['trailList'][0].keys)

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The trail named {self.trail_name} does not have encryption " \
               f"enabled. "


def lambda_handler(event, _):
    """ Handles the incoming event """
    rule = ReflexAwsCloudtrailNotEncrypted(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
