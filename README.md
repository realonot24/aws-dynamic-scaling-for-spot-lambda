# aws-dynamic-scaling-for-spot-lambda

 AWS Dynamic Scaling for Spot Lambda

A robust AWS Lambda-based solution designed to handle dynamic scaling of EC2 instances, specifically tailored for spot instances. This project is ideal for optimizing cloud costs while ensuring seamless transitions during spot interruptions or resource scaling events.

---

## Features

- **Dynamic Spot Instance Handling**: Automatically manages EC2 spot instance interruptions and performs failover to on-demand instances.
- **Scalable Architecture**: Adjusts the EC2 instance type up or down based on predefined utilization thresholds.
- **Cost Optimization**: Minimizes cloud costs by prioritizing spot instances over on-demand where applicable.
- **Automated Snapshots**: Creates snapshots of attached volumes before instance termination for data safety.
- **Custom Scaling Rules**: Configure thresholds for CPU and memory utilization to suit your application needs.
- **Integrated CloudWatch Alarms**: Automatically updates or disables alarms during scaling events.
- **Email Notifications**: Sends email notifications for critical events using AWS SNS.

---

## Prerequisites

1. **AWS Account**: Ensure you have access to an AWS account with permissions to manage EC2, Lambda, CloudWatch, and SNS resources.
2. **Python Environment**: Python 3.7+ is required for local testing and development.
3. **AWS SDK for Python (boto3)**: Install boto3 using `pip install boto3`.
4. **IAM Role**:
   - Lambda requires an IAM role with permissions for EC2, SNS, and CloudWatch actions.
   - Example policy:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": [
             "ec2:*",
             "sns:*",
             "cloudwatch:*"
           ],
           "Resource": "*"
         }
       ]
     }
     ```

---

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/realonot24/aws-dynamic-scaling-for-spot-lambda.git
   cd aws-dynamic-scaling-for-spot-lambda
Deploy the Lambda Function:

Package the code and upload it to AWS Lambda.
Ensure the Lambda function is triggered by appropriate CloudWatch alarms and spot instance events.
Environment Variables: Set the following environment variables in your Lambda function:

AWS_REGION: Default region (e.g., us-east-2).
EC2_NAME_TAG_KEY: Tag key for identifying EC2 instances (e.g., Name).
SNS_TOPIC_TAG_KEY and SNS_TOPIC_TAG_VALUE: Tags for the SNS topic.
CloudWatch Alarms: Configure CloudWatch alarms for CPU and memory utilization thresholds. Example:

CPU Utilization High: > 50% for 10 minutes.
CPU Utilization Low: < 15% for 30 minutes.
Test the Solution:

Simulate spot interruptions or high/low resource usage to verify the scaling logic.
