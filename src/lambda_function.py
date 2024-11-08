import boto3
import time
import datetime
import logging
import botocore.exceptions
from botocore.exceptions import ClientError
import random
import os
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ec2 = boto3.client('ec2')
sns = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')
sts_client = boto3.client('sts')
ACCOUNT_ID = sts_client.get_caller_identity()['Account']
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-2')  # Default region if not set
lambda_client = boto3.client('lambda', region_name=AWS_REGION)

# ====================================================================
# Constants and Configuration Parameters
# ====================================================================

# Tag names and values to identify resources
EC2_NAME_TAG_KEY = 'Name'  # Tag key used to identify EC2 instances

# ====================================================================
# Scaling Configuration Constants: INSTANCE_SCALE_SEQUENCE and SMALLEST_INSTANCES
# ====================================================================

# Overview:
# These constants define the scaling configuration for EC2 instances used in the code:
# - `INSTANCE_SCALE_SEQUENCE`: Defines the hierarchy and order for scaling EC2 instances.
# - `SMALLEST_INSTANCES`: Specifies instances that should not be scaled down.

# `INSTANCE_SCALE_SEQUENCE`:
# - Each entry in this list specifies the order (indexed from 0) and relative type of each instance
#   for scaling actions, from the smallest to the largest instance.
# - Position in the list (by index) determines the scaling sequence, while the 'Name' key is used
#   to locate the instance by tag.
# - The 'Type' key is informational only, providing a reference for the intended AWS instance type.
#   It is not enforced in the code and will not impact instance matching or actions on AWS.

# **IMPORTANT: Correct AWS `Name` Tags Required**:
# - The code identifies and scales instances using only the `Name` tag defined in `INSTANCE_SCALE_SEQUENCE`,
#   not the actual AWS instance type.
# - A mismatch between `Name` tags and actual instance types can lead to unexpected outcomes, including:
#     1. **Higher costs** due to unintended resource usage.
#     2. **Inaccurate scaling**: For example, if a large instance is tagged as a medium instance, the system may
#        assume it’s a medium instance, leading to earlier scaling actions based on incorrect capacity assumptions.
#     3. **Misleading logs**: Monitoring logs will display the specified type (e.g., medium), masking actual instance costs.
#
# Example Scenario:
# - If `Name` tag `'ron.si.CC.m'` (intended for a medium instance) is mistakenly assigned to an `m5.2xlarge` instance,
#   the code will treat it as a medium instance. This will cause:
#     a. Increased costs, as an `m5.2xlarge` incurs higher charges than a medium.
#     b. Over-provisioning, as the code may scale up sooner than needed.
#     c. Confusing logs that refer to it as a medium instance, masking the true cost.
# - Solution: Ensure each `Name` tag aligns with the actual instance type and hierarchy intended in `INSTANCE_SCALE_SEQUENCE`.
# - Recommendation: Regularly verify that AWS instances and their `Name` tags are consistent with this configuration.

# Modifying `INSTANCE_SCALE_SEQUENCE`:
# - Adding a Level: To introduce a larger instance type, add a new entry at the desired position in the list.
# - Removing a Level: Remove an entry to skip that instance type in scaling actions.
# - Reordering Levels: Adjusting an instance’s position changes when it is accessed in the scaling sequence,
#   which can affect operational costs (e.g., moving a larger instance to an earlier position).

# Examples:
# 1. Adding an Instance:
#    Adding {'Name': 'ron.si.F.2xl', 'Type': 't3a.2xlarge'} at the end of the list (index 5)
#    enables scaling up beyond 't3a.xlarge' if resource demand requires it.
# 2. Reordering Instances:
#    Moving {'Name': 'ron.si.E.xl', 'Type': 't3a.xlarge'} to an earlier position, such as index 2,
#    makes it available sooner in the scaling sequence, potentially increasing operational costs.

# `SMALLEST_INSTANCES`:
# - This list includes instances that should not be scaled down further, serving as the minimum scaling floor.
# - Instances listed here will not be considered for downscaling actions.

# Modifying `SMALLEST_INSTANCES`:
# - Adding an instance here prevents it from being scaled down even if usage drops below threshold.
# - Removing an instance allows it to be downscaled, offering more flexibility and potential cost savings.

# Examples:
# 1. Adding to `SMALLEST_INSTANCES`:
#    Adding 'ron.si.D.l' to `SMALLEST_INSTANCES` prevents scaling down from `t3a.large`,
#    setting `t3a.large` as the minimum instance size.
# 2. Reducing smallest instances:
#    Removing an instance from `SMALLEST_INSTANCES` allows it to scale down further, optimizing costs.

# ====================================================================
# List of EC2 instances with their types in the scaling sequence
# Modify this list to add or remove instances
INSTANCE_SCALE_SEQUENCE = [
    # {'Name': os.environ.get('EC2_A_NAME_TAG', 'ron.si.A.s'), 'Type': 't3a.small'},
    # {'Name': os.environ.get('EC2_B_NAME_TAG', 'ron.si.B.s'), 'Type': 't3a.small'},
    {'Name': os.environ.get('EC2_C_NAME_TAG', 'ron.si.C.m'), 'Type': 't3a.medium'},
    {'Name': os.environ.get('EC2_C_NAME_TAG', 'ron.si.CCCC.m'), 'Type': 't3.medium'},
    {'Name': os.environ.get('EC2_CC_NAME_TAG', 'ron.si.CC.m'), 'Type': 't3a.medium'},
    {'Name': os.environ.get('EC2_C_NAME_TAG', 'ron.si.CCC.m'), 'Type': 't3.medium'},
    {'Name': os.environ.get('EC2_D_NAME_TAG', 'ron.si.D.l'), 'Type': 't3a.large'},
    {'Name': os.environ.get('EC2_E_NAME_TAG', 'ron.si.E.xl'), 'Type': 't3a.xlarge'},
    # Add more instances as needed
    # {'Name': 'ron.si.F.2xl', 'Type': 't3a.2xlarge'},
    # {'Name': 'ron.si.G.4xl', 'Type': 't3a.4xlarge'},
]

# Instances considered smallest (cannot scale down)
SMALLEST_INSTANCES = [INSTANCE_SCALE_SEQUENCE[0]['Name'], INSTANCE_SCALE_SEQUENCE[1]['Name'], INSTANCE_SCALE_SEQUENCE[2]['Name'], INSTANCE_SCALE_SEQUENCE[3]['Name']]

# CPU and Memory Utilization Thresholds for Scaling Up (in percentage)
CPU_UP_THRESHOLD = 50  # Default CPU threshold for scaling up
MEMORY_UP_THRESHOLD = 70  # Default Memory threshold for scaling up

# Scaling thresholds (CPU utilization) for scaling down
CPU_DOWN_THRESHOLD = 15  # Below 15% CPU utilization for scaling down

# Duration thresholds in seconds
CPU_UP_DURATION = 600      # Duration for scaling up (in seconds) (Default 10 minutes)
CPU_DOWN_DURATION = 1800   # Duration for scaling down (in seconds) (Default 30 minutes)

# Number of levels to scale down (configurable)
SCALE_DOWN_LEVELS = int(os.environ.get('SCALE_DOWN_LEVELS', 1))  # Default is 1 level down

# Wait time in seconds for users to wrap up their work before switching
USER_WAIT_TIME = 80  # 80 seconds

# CloudWatch Namespace and Metric Names
CW_NAMESPACE = 'AWS/EC2'
CPU_METRIC_NAME = 'CPUUtilization'
MEMORY_METRIC_NAME = 'MemoryUtilization'  # Requires CloudWatch agent

# Tag names and values for other resources
ELASTIC_IP_NAME_TAG = os.environ.get('ELASTIC_IP_NAME_TAG', 'ron.eip.main')  # Tag value for Elastic IP
SNS_TOPIC_TAG_KEY = os.environ.get('SNS_TOPIC_TAG_KEY', 'ron.sns')  # Tag key for SNS topic
SNS_TOPIC_TAG_VALUE = os.environ.get('SNS_TOPIC_TAG_VALUE', '24')   # Tag value for SNS topic

# Alarm Prefix
ALARM_NAME_PREFIX = 'RoN_Dyn_Scal_Alarm'

# Configuration to Enable or Disable Memory Utilization in Scaling Decisions
USE_MEMORY_METRICS = os.environ.get('USE_MEMORY_METRICS', 'N')  # Default is 'N'; change to 'Y' to enable memory metrics

# General Retry and Wait Configuration
DELAY_SECONDS = 12  # Default delay between retries and waits
MAX_RETRIES = 9     # Default maximum number of retries
MAX_ATTEMPTS = 9    # Default maximum number of attempts for AWS waiters

# ====================================================================
# Global Variables for Execution Logging
# ====================================================================

execution_log = []  # List to collect execution steps
error_occurred = False  # Flag to indicate if an error occurred
LAMBDA_FUNCTION_ARN = ''  # Global variable to store Lambda function ARN
sns_topic_arn_global = None  # Global variable for SNS Topic ARN to be used in retries

# ====================================================================
# Lambda Handler
# ====================================================================

def lambda_handler(event, context):
    global error_occurred
    global LAMBDA_FUNCTION_ARN  # Declare global variable
    global sns_topic_arn_global  # Declare global variable
    LAMBDA_FUNCTION_ARN = context.invoked_function_arn  # Get the Lambda function ARN
    start_time = datetime.datetime.utcnow()
    try:
        # Retrieve SNS topic ARN based on tags
        sns_topic_arn = get_sns_topic_arn_by_tag(SNS_TOPIC_TAG_KEY, SNS_TOPIC_TAG_VALUE)
        sns_topic_arn_global = sns_topic_arn  # Assign to global variable for use in retries
        if not sns_topic_arn:
            add_execution_log("Could not retrieve SNS topic ARN based on tags. Exiting.")
            return

        # Determine the type of event
        detail_type = event.get('detail-type')
        if detail_type == 'EC2 Spot Instance Interruption Warning':
            # Handle spot instance termination
            add_execution_log("Received EC2 Spot Instance Interruption Warning.")
            send_initial_email(sns_topic_arn, event)
            handle_spot_instance_termination(event, sns_topic_arn)
        elif detail_type == 'CloudWatch Alarm State Change':
            # Handle alarm events
            add_execution_log("Received CloudWatch Alarm State Change event.")
            send_initial_email(sns_topic_arn, event)
            handle_alarm_event(event, sns_topic_arn)
        else:
            # Handle scaling logic
            add_execution_log("Starting scaling logic.")
            send_initial_email(sns_topic_arn, event)
            handle_scaling_logic(event, sns_topic_arn)

    except Exception as e:
        error_occurred = True
        error_message = f"Unexpected error: {str(e)}\n{traceback.format_exc()}"
        add_execution_log(error_message)
        send_error_email(sns_topic_arn, "Unexpected Error", error_message)
    finally:
        # Send summary email
        send_summary_email(sns_topic_arn)

# ====================================================================
# Function to Handle Spot Instance Termination Warning
# ====================================================================

def handle_spot_instance_termination(event, sns_topic_arn):
    global error_occurred
    try:
        instance_id = event['detail']['instance-id']
        add_execution_log(f"Handling spot instance termination warning for instance {instance_id}")

        # Get the name of the instance that is being terminated
        instance_name = get_instance_name_by_id(instance_id)
        if not instance_name:
            add_execution_log("Could not retrieve instance name. Exiting.")
            return

        # Determine the target instance to switch to
        target_instance_name = get_next_instance_name_for_termination(instance_name)
        if not target_instance_name:
            add_execution_log("No target instance available for failover. Exiting.")
            return

        target_instance_id = get_instance_id_by_name_tag(target_instance_name)
        if not target_instance_id:
            add_execution_log(f"Target instance {target_instance_name} does not exist. Exiting.")
            return

        # Record initial action
        add_execution_log(f"Initiating failover from {instance_name} ({instance_id}) to {target_instance_name} ({target_instance_id}).")

        # Disable alarms for the instance being terminated
        disable_alarms_for_instance(instance_name)

        # Retrieve the volume attached to the instance
        volume_id, original_device_name = get_attached_volume(instance_id)
        if not volume_id:
            add_execution_log(f"No volumes found attached to instance {instance_id}. Exiting.")
            return

        # Start creating the snapshot immediately
        snapshot_name = f"Pre Termination Backup {instance_name}"
        snapshot_id = create_and_tag_snapshot(volume_id, snapshot_name)
        if not snapshot_id:
            add_execution_log(f"Failed to create snapshot for volume {volume_id}. Exiting.")
            return

        # Start the user wait time concurrently
        add_execution_log(f"Waiting for users to stop work before terminating instance {instance_name}.")
        wait_for_users(USER_WAIT_TIME)

        # Proceed with stopping the instance
        add_execution_log(f"Stopping instance {instance_name} ({instance_id})")
        retry_with_backoff(lambda: ec2.stop_instances(InstanceIds=[instance_id]))

        # Wait until the instance is stopped with timeout
        add_execution_log(f"Waiting for instance {instance_name} ({instance_id}) to stop.")
        waiter = ec2.get_waiter('instance_stopped')
        waiter.wait(
            InstanceIds=[instance_id],
            WaiterConfig={
                'Delay': DELAY_SECONDS,
                'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
            }
        )

        # Proceed with detaching volume from the stopped instance
        add_execution_log(f"Detaching volume {volume_id} from instance {instance_name} ({instance_id})")
        if ensure_volume_is_attached(volume_id, instance_id):
            retry_with_backoff(lambda: ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id, Force=True))
        else:
            add_execution_log(f"Skipping detachment for volume {volume_id}.")

        # Wait until the volume is available with timeout
        add_execution_log(f"Waiting for volume {volume_id} to become available.")
        waiter = ec2.get_waiter('volume_available')
        waiter.wait(
            VolumeIds=[volume_id],
            WaiterConfig={
                'Delay': DELAY_SECONDS,
                'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
            }
        )

        # Ensure the snapshot is complete before proceeding
        if not wait_for_snapshot_completion(snapshot_id):
            add_execution_log(f"Snapshot {snapshot_id} did not complete successfully. Exiting.")
            return

        # Start the failover process
        perform_failover(instance_name, target_instance_name, volume_id, sns_topic_arn)

    except Exception as e:
        error_occurred = True
        error_message = f"Error handling spot instance termination: {str(e)}\n{traceback.format_exc()}"
        add_execution_log(error_message)
        send_error_email(sns_topic_arn, "Error Handling Spot Instance Termination", error_message)

# ====================================================================
# Function to Handle Scaling Logic
# ====================================================================

def handle_scaling_logic(event, sns_topic_arn):
    global error_occurred
    try:
        # Check if test_mode is enabled
        test_mode = event.get('test_mode', False)
        test_data = event.get('test_data', {})

        # Step 1: Identify the currently running instance
        current_instance = get_current_instance(test_mode=test_mode, test_data=test_data)
        if not current_instance:
            add_execution_log("No running instance found. Exiting.")
            return

        instance_id = current_instance['InstanceId']
        instance_type = current_instance['InstanceType']
        instance_name = get_instance_name(current_instance)
        add_execution_log(f"Monitoring instance {instance_id} ({instance_name}) of type {instance_type}")

        # Step 2: Check and set alarms for the current instance
        manage_alarms_for_instance(instance_id, instance_name)

        # Step 3: Check if scaling up is needed
        scale_up = check_scale_up(instance_id, test_mode=test_mode, test_data=test_data)

        # Step 4: Check if scaling down is needed
        scale_down = check_scale_down(current_instance, test_mode=test_mode, test_data=test_data)

        # Step 5: Decide on scaling action
        if scale_up:
            target_instance_name = get_next_instance_name(instance_name, direction='up')
            if target_instance_name:
                perform_scaling_action(instance_name, target_instance_name, sns_topic_arn)
            else:
                add_execution_log("Already at the highest instance type or target instance not available. No scaling up performed.")
                # Attempt to scale down if scaling up is not possible
                if instance_name not in SMALLEST_INSTANCES:
                    add_execution_log("Attempting to scale down since scaling up is not possible.")
                    target_instance_name = get_next_instance_name(instance_name, direction='down', levels=SCALE_DOWN_LEVELS)
                    if target_instance_name:
                        perform_scaling_action(instance_name, target_instance_name, sns_topic_arn)
                    else:
                        add_execution_log("Cannot scale down further. No scaling action performed.")
        elif scale_down:
            target_instance_name = get_next_instance_name(instance_name, direction='down', levels=SCALE_DOWN_LEVELS)
            if target_instance_name:
                perform_scaling_action(instance_name, target_instance_name, sns_topic_arn)
            else:
                add_execution_log("Already at the initial instance or cannot scale down further. No scaling down performed.")
        else:
            add_execution_log("No scaling action required at this time.")

    except Exception as e:
        error_occurred = True
        error_message = f"Error in scaling logic: {str(e)}\n{traceback.format_exc()}"
        add_execution_log(error_message)
        send_error_email(sns_topic_arn, "Error in Scaling Logic", error_message)

# ====================================================================
# Function to Handle CloudWatch Alarm Events
# ====================================================================

def handle_alarm_event(event, sns_topic_arn):
    global error_occurred
    try:
        alarm_name = event['detail']['alarmName']
        alarm_state = event['detail']['state']['value']
        add_execution_log(f"Handling alarm event for {alarm_name}, new state: {alarm_state}")

        # Determine the instance associated with the alarm
        instance_name = get_instance_name_from_alarm(alarm_name)
        if not instance_name:
            add_execution_log(f"Could not determine instance name from alarm {alarm_name}. Exiting.")
            return

        # Get the instance ID from the name tag
        instance_id = get_instance_id_by_name_tag(instance_name)
        if not instance_id:
            add_execution_log(f"Could not retrieve instance ID for instance {instance_name}. Exiting.")
            return

        # Check the state of the instance before acting
        instance_state = get_instance_state(instance_id)
        if instance_state != 'running':
            add_execution_log(f"Instance {instance_name} ({instance_id}) is in state {instance_state}. No scaling action taken.")
            return

        # Handle the alarm state
        if alarm_state == 'ALARM':
            # Depending on the alarm type, decide whether to scale up or down
            if 'CPU-High' in alarm_name or 'Memory-High' in alarm_name:
                add_execution_log(f"High utilization alarm triggered for instance {instance_name}. Considering scaling up.")
                target_instance_name = get_next_instance_name(instance_name, direction='up')
                if target_instance_name:
                    perform_scaling_action(instance_name, target_instance_name, sns_topic_arn)
                else:
                    add_execution_log("Already at the highest instance type or target instance not available. No scaling up performed.")
                    # Attempt to scale down if scaling up is not possible
                    if instance_name not in SMALLEST_INSTANCES:
                        add_execution_log("Attempting to scale down since scaling up is not possible.")
                        target_instance_name = get_next_instance_name(instance_name, direction='down', levels=SCALE_DOWN_LEVELS)
                        if target_instance_name:
                            perform_scaling_action(instance_name, target_instance_name, sns_topic_arn)
                        else:
                            add_execution_log("Cannot scale down further. No scaling action performed.")
            elif 'CPU-Low' in alarm_name:
                add_execution_log(f"Low CPU utilization alarm triggered for instance {instance_name}. Considering scaling down.")
                target_instance_name = get_next_instance_name(instance_name, direction='down', levels=SCALE_DOWN_LEVELS)
                if target_instance_name:
                    perform_scaling_action(instance_name, target_instance_name, sns_topic_arn)
                else:
                    add_execution_log("Already at the initial instance or cannot scale down further. No scaling down performed.")
            else:
                add_execution_log(f"Unhandled alarm type for {alarm_name}.")
        else:
            add_execution_log(f"Alarm {alarm_name} is in state {alarm_state}. No action taken.")

    except Exception as e:
        error_occurred = True
        error_message = f"Error handling alarm event: {str(e)}\n{traceback.format_exc()}"
        add_execution_log(error_message)
        send_error_email(sns_topic_arn, "Error Handling Alarm Event", error_message)

# ====================================================================
# Helper Functions
# ====================================================================

def add_execution_log(message):
    """
    Adds a timestamped message to the execution log.
    """
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    execution_log.append(f"[{timestamp}] {message}")
    logger.info(message)

def send_initial_email(sns_topic_arn, event):
    """
    Sends an initial email when the Lambda function starts.
    """
    detail_type = event.get('detail-type', 'Scaling Event')
    message = f"Lambda function started.\nEvent Type: {detail_type}\n"
    if detail_type == 'EC2 Spot Instance Interruption Warning':
        instance_id = event['detail']['instance-id']
        instance_name = get_instance_name_by_id(instance_id)
        message += f"Spot instance {instance_name} ({instance_id}) is marked for termination.\n"
    elif detail_type == 'CloudWatch Alarm State Change':
        alarm_name = event['detail']['alarmName']
        alarm_state = event['detail']['state']['value']
        message += f"Alarm {alarm_name} changed state to {alarm_state}.\n"
    else:
        current_instance = get_current_instance()
        if current_instance:
            instance_id = current_instance['InstanceId']
            instance_name = get_instance_name(current_instance)
            message += f"Current running instance: {instance_name} ({instance_id})\n"
        else:
            message += "No running instance found.\n"
    send_email(sns_topic_arn, "Lambda Function Execution Started", message)

def send_summary_email(sns_topic_arn):
    """
    Sends a summary email at the end of the execution.
    """
    subject = "Lambda Function Execution Summary"
    if error_occurred:
        subject = "Lambda Function Execution Summary with Errors"
    message = "Execution Summary:\n\n" + "\n".join(execution_log)
    send_email(sns_topic_arn, subject, message)

def send_error_email(sns_topic_arn, subject, message):
    """
    Sends an immediate email in case of errors after retries exceed 2.
    """
    send_email(sns_topic_arn, subject, message)

def send_email(sns_topic_arn, subject, message):
    """
    Sends an email with the provided subject and message to the specified SNS topic ARN.
    """
    try:
        sns.publish(
            TopicArn=sns_topic_arn,
            Message=message,
            Subject=subject
        )
        logger.info(f"Email sent: {subject}")
    except ClientError as e:
        logger.error(f"Error sending email: {e.response['Error']['Message']}")

def get_current_instance(test_mode=False, test_data=None):
    """
    Retrieves the currently running instance from the scaling sequence.
    If test_mode is True, returns mock data from test_data.
    """
    if test_mode and test_data:
        add_execution_log("Test mode enabled. Using simulated current instance.")
        return test_data.get('current_instance')
    else:
        try:
            instance_names = [inst['Name'] for inst in INSTANCE_SCALE_SEQUENCE]
            response = ec2.describe_instances(
                Filters=[
                    {'Name': f'tag:{EC2_NAME_TAG_KEY}', 'Values': instance_names},
                    {'Name': 'instance-state-name', 'Values': ['running']}
                ]
            )
            reservations = response['Reservations']
            if reservations:
                for reservation in reservations:
                    instances = reservation['Instances']
                    if instances:
                        return instances[0]
            return None
        except Exception as e:
            add_execution_log(f"Error retrieving current instance: {str(e)}")
            return None

def get_instance_name(instance):
    """
    Retrieves the 'Name' tag value of an instance.
    """
    for tag in instance.get('Tags', []):
        if tag['Key'] == EC2_NAME_TAG_KEY:
            return tag['Value']
    return None

def get_instance_name_by_id(instance_id):
    """
    Retrieves the 'Name' tag value of an instance given its ID.
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instances = response['Reservations'][0]['Instances']
        if instances:
            return get_instance_name(instances[0])
        else:
            return None
    except Exception as e:
        add_execution_log(f"Error retrieving instance name for ID {instance_id}: {str(e)}")
        return None

def get_next_instance_name(current_name, direction='up', levels=1):
    """
    Determines the next instance name for scaling up or down based on the scaling sequence.
    """
    instance_names = [inst['Name'] for inst in INSTANCE_SCALE_SEQUENCE]
    try:
        current_index = instance_names.index(current_name)
    except ValueError:
        add_execution_log(f"Current instance name {current_name} not found in scaling sequence.")
        return None

    if direction == 'up':
        if current_name in SMALLEST_INSTANCES:
            # Find the highest index of SMALLEST_INSTANCES
            smallest_indices = [instance_names.index(name) for name in SMALLEST_INSTANCES if name in instance_names]
            max_smallest_index = max(smallest_indices)
            target_index = max_smallest_index + 1
        else:
            target_index = current_index + 1

        while target_index < len(instance_names):
            target_instance_name = instance_names[target_index]
            target_instance_id = get_instance_id_by_name_tag(target_instance_name)
            target_instance_state = get_instance_state(target_instance_id)
            if target_instance_id and target_instance_state == 'stopped':
                return target_instance_name
            else:
                add_execution_log(f"Target instance {target_instance_name} not available for scaling up.")
                target_index += 1
        return None  # No higher instance available
    elif direction == 'down':
        target_index = max(0, current_index - levels)
        if target_index < current_index:
            return instance_names[target_index]
        else:
            return None  # Already at lowest tier
    else:
        return None

def get_next_instance_name_for_termination(current_name):
    """
    Determines the next instance name to fail over to upon spot instance termination.
    """
    instance_names = [inst['Name'] for inst in INSTANCE_SCALE_SEQUENCE]
    try:
        current_index = instance_names.index(current_name)
    except ValueError:
        add_execution_log(f"Current instance name {current_name} not found in scaling sequence.")
        return None

    # Move down one level; if at the bottom, switch to the other smallest instance
    if current_name == SMALLEST_INSTANCES[0]:
        return SMALLEST_INSTANCES[1]
    elif current_name == SMALLEST_INSTANCES[1]:
        return SMALLEST_INSTANCES[0]
    elif current_index > 0:
        return instance_names[current_index - 1]
    else:
        return None

def check_scale_up(instance_id, test_mode=False, test_data=None):
    """
    Checks if scaling up is required based on CPU (and memory if enabled) utilization.
    In test mode, uses simulated CPU (and memory) utilization from test_data.
    """
    cpu_threshold = CPU_UP_THRESHOLD
    memory_threshold = MEMORY_UP_THRESHOLD if USE_MEMORY_METRICS == 'Y' else None

    if test_mode and test_data:
        # Test mode: use simulated metrics
        cpu_utilization = test_data.get('cpu_utilization', None)
        memory_utilization = test_data.get('memory_utilization', None) if USE_MEMORY_METRICS == 'Y' else None
        add_execution_log(f"Test mode enabled. Simulated CPU utilization: {cpu_utilization}, Memory utilization: {memory_utilization}")
    else:
        # Production mode: retrieve actual metrics from CloudWatch
        cpu_utilization = get_metric_statistics(instance_id, CPU_METRIC_NAME, CPU_UP_DURATION)
        if USE_MEMORY_METRICS == 'Y':
            memory_utilization = get_metric_statistics(instance_id, MEMORY_METRIC_NAME, CPU_UP_DURATION)
        else:
            memory_utilization = None

    if cpu_utilization is not None and cpu_utilization > cpu_threshold:
        add_execution_log(f"CPU utilization {cpu_utilization}% exceeds threshold {cpu_threshold}% for instance {instance_id}")
        return True

    if USE_MEMORY_METRICS == 'Y' and memory_utilization is not None and memory_utilization > memory_threshold:
        add_execution_log(f"Memory utilization {memory_utilization}% exceeds threshold {memory_threshold}% for instance {instance_id}")
        return True

    return False

def check_scale_down(instance, test_mode=False, test_data=None):
    """
    Checks if scaling down is required based on CPU utilization over the specified duration.
    """
    instance_id = instance['InstanceId']
    instance_name = get_instance_name(instance)
    if instance_name in SMALLEST_INSTANCES:
        add_execution_log(f"Instance {instance_name} is one of the smallest instances. Cannot scale down.")
        return False

    if test_mode and test_data:
        # Test mode: use simulated metrics
        cpu_utilization = test_data.get('cpu_utilization', None)
        add_execution_log(f"Test mode enabled. Simulated CPU utilization: {cpu_utilization}")
    else:
        # Production mode: retrieve actual metrics from CloudWatch
        cpu_utilization = get_metric_statistics(instance_id, CPU_METRIC_NAME, CPU_DOWN_DURATION)

    if cpu_utilization is not None and cpu_utilization < CPU_DOWN_THRESHOLD:
        add_execution_log(f"CPU utilization {cpu_utilization}% is below threshold {CPU_DOWN_THRESHOLD}% for instance {instance_id}")
        return True

    return False

def get_metric_statistics(instance_id, metric_name, duration_seconds):
    """
    Retrieves the average metric value over the specified duration.
    """
    try:
        end_time = datetime.datetime.utcnow()
        start_time = end_time - datetime.timedelta(seconds=duration_seconds)
        period = calculate_alarm_period(duration_seconds)
        response = cloudwatch.get_metric_statistics(
            Namespace=CW_NAMESPACE if metric_name != MEMORY_METRIC_NAME else 'CWAgent',
            MetricName=metric_name,
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,  # Period of each data point
            Statistics=['Average']
        )
        data_points = response['Datapoints']
        if data_points:
            # Calculate the average over all data points
            averages = [dp['Average'] for dp in data_points]
            overall_average = sum(averages) / len(averages)
            return overall_average
        else:
            add_execution_log(f"No data points retrieved for metric {metric_name} on instance {instance_id}")
            return None
    except Exception as e:
        add_execution_log(f"Error retrieving metric {metric_name} for instance {instance_id}: {str(e)}")
        return None

def perform_scaling_action(current_name, target_name, sns_topic_arn, attempted_instance_names=None):
    """
    Performs the scaling action by stopping the current instance, switching volumes, and starting the target instance.
    """
    global error_occurred
    if attempted_instance_names is None:
        attempted_instance_names = []
    attempted_instance_names.append(target_name)

    try:
        add_execution_log(f"Initiating scaling action from {current_name} to {target_name}")

        # Retrieve instance IDs based on names
        current_instance_id = get_instance_id_by_name_tag(current_name)
        target_instance_id = get_instance_id_by_name_tag(target_name)

        if not current_instance_id or not target_instance_id:
            add_execution_log("Could not retrieve instance IDs based on names. Exiting.")
            return

        # Disable alarms for the current instance
        disable_alarms_for_instance(current_name)

        # Retrieve the volume attached to the current instance
        volume_id, original_device_name = get_attached_volume(current_instance_id)
        if not volume_id:
            add_execution_log(f"No volumes found attached to instance {current_instance_id}. Exiting.")
            return

        # Start creating the snapshot immediately
        snapshot_name = f"Scaling Snapshot {current_name}"
        snapshot_id = create_and_tag_snapshot(volume_id, snapshot_name)
        if not snapshot_id:
            add_execution_log(f"Failed to create snapshot for volume {volume_id}. Exiting.")
            return

        # Start the user wait time concurrently
        add_execution_log(f"Waiting for users to stop work before switching instances.")
        wait_for_users(USER_WAIT_TIME)

        # Proceed with stopping the current instance
        add_execution_log(f"Stopping instance {current_name} ({current_instance_id})")
        retry_with_backoff(lambda: ec2.stop_instances(InstanceIds=[current_instance_id]))

        # Wait until the instance is stopped with timeout
        add_execution_log(f"Waiting for instance {current_name} ({current_instance_id}) to stop.")
        waiter = ec2.get_waiter('instance_stopped')
        waiter.wait(
            InstanceIds=[current_instance_id],
            WaiterConfig={
                'Delay': DELAY_SECONDS,
                'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
            }
        )

        # Proceed with detaching volume from the stopped instance
        add_execution_log(f"Detaching volume {volume_id} from instance {current_name} ({current_instance_id})")
        if ensure_volume_is_attached(volume_id, current_instance_id):
            retry_with_backoff(lambda: ec2.detach_volume(VolumeId=volume_id, InstanceId=current_instance_id, Force=True))
        else:
            add_execution_log(f"Skipping detachment for volume {volume_id}.")

        # Wait until the volume is available with timeout
        add_execution_log(f"Waiting for volume {volume_id} to become available.")
        waiter = ec2.get_waiter('volume_available')
        waiter.wait(
            VolumeIds=[volume_id],
            WaiterConfig={
                'Delay': DELAY_SECONDS,
                'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
            }
        )

        # Ensure the snapshot is complete before proceeding
        if not wait_for_snapshot_completion(snapshot_id):
            add_execution_log(f"Snapshot {snapshot_id} did not complete successfully. Exiting.")
            return

        # Start the failover process
        perform_failover(current_name, target_name, volume_id, sns_topic_arn, attempted_instance_names)

    except Exception as e:
        error_occurred = True
        error_message = f"Error performing scaling action: {str(e)}\n{traceback.format_exc()}"
        add_execution_log(error_message)
        send_error_email(sns_topic_arn, "Error Performing Scaling Action", error_message)

def perform_failover(current_name, target_name, volume_id, sns_topic_arn, attempted_instance_names=None):
    """
    Performs the failover process to the target instance. If InsufficientInstanceCapacity error occurs,
    it retries starting the instance up to max_retries times before attempting to fail over to another instance.
    """
    global error_occurred
    if attempted_instance_names is None:
        attempted_instance_names = []
    attempted_instance_names.append(target_name)

    try:
        target_instance_id = get_instance_id_by_name_tag(target_name)
        if not target_instance_id:
            add_execution_log(f"Target instance {target_name} does not exist. Exiting.")
            return

        # Validate target instance state
        target_instance_state = get_instance_state(target_instance_id)
        if target_instance_state != 'stopped':
            add_execution_log(f"Target instance {target_instance_id} is not in 'stopped' state, cannot proceed.")
            return

        # Attach the volume to the target instance as root
        attach_volume_to_target_instance(target_instance_id, volume_id)

        # Reassign Elastic IP to the new instance
        elastic_ip_allocation_id = get_elastic_ip_allocation_by_name_tag(ELASTIC_IP_NAME_TAG)
        if elastic_ip_allocation_id:
            add_execution_log(f"Reassigning Elastic IP to instance {target_name} ({target_instance_id})")
            retry_with_backoff(lambda: ec2.associate_address(
                AllocationId=elastic_ip_allocation_id,
                InstanceId=target_instance_id,
                AllowReassociation=True
            ))
        else:
            add_execution_log(f"Elastic IP with tag '{ELASTIC_IP_NAME_TAG}' not found.")
            return

        # Start the target instance with retries
        add_execution_log(f"Starting instance {target_name} ({target_instance_id}) with up to {MAX_RETRIES} retries.")
        try:
            start_instance_with_retries(target_instance_id, target_name, max_retries=MAX_RETRIES, delay=DELAY_SECONDS)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InsufficientInstanceCapacity':
                add_execution_log(f"Insufficient capacity to start instance {target_name} after max retries.")
                # Detach the volume before retrying failover
                add_execution_log(f"Detaching volume {volume_id} from instance {target_name} ({target_instance_id}) due to start failure.")
                if ensure_volume_is_attached(volume_id, target_instance_id):
                    retry_with_backoff(lambda: ec2.detach_volume(VolumeId=volume_id, InstanceId=target_instance_id, Force=True))
                else:
                    add_execution_log(f"Volume {volume_id} is not attached to instance {target_instance_id}. Skipping detachment.")
                # Wait until the volume is available with timeout
                add_execution_log(f"Waiting for volume {volume_id} to become available.")
                waiter = ec2.get_waiter('volume_available')
                waiter.wait(
                    VolumeIds=[volume_id],
                    WaiterConfig={
                        'Delay': DELAY_SECONDS,
                        'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
                    }
                )

                # Attempt to switch to the next level up or down
                next_target_name_up = get_next_instance_name(target_name, direction='up')
                next_target_name_down = get_next_instance_name(target_name, direction='down')
                if next_target_name_up and next_target_name_up not in attempted_instance_names:
                    add_execution_log(f"Attempting to switch to the next level up: {next_target_name_up}")
                    perform_failover(current_name, next_target_name_up, volume_id, sns_topic_arn, attempted_instance_names)
                    return  # Added return
                elif next_target_name_down and next_target_name_down not in attempted_instance_names:
                    add_execution_log(f"Attempting to switch to the next level down: {next_target_name_down}")
                    perform_failover(current_name, next_target_name_down, volume_id, sns_topic_arn, attempted_instance_names)
                    return  # Added return
                else:
                    add_execution_log("No other instances available or already attempted. Exiting.")
                    raise e
            else:
                raise e

        # Wait until the instance is running with timeout
        add_execution_log(f"Waiting for instance {target_name} ({target_instance_id}) to start.")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(
            InstanceIds=[target_instance_id],
            WaiterConfig={
                'Delay': DELAY_SECONDS,
                'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
            }
        )

        # Tagging instances for state tracking
        add_execution_log(f"Tagging instance {target_name} ({target_instance_id}) as 'LastUsed'")
        all_instance_ids = get_all_instance_ids()
        tag_instance_as_last_used(target_instance_id, all_instance_ids)

        # Enable alarms for the target instance
        manage_alarms_for_instance(target_instance_id, target_name)

        # Record completion
        add_execution_log(f"Failover to {target_name} ({target_instance_id}) completed successfully.")
        return  # Added return

    except Exception as e:
        error_occurred = True
        error_message = f"Error during failover: {str(e)}\n{traceback.format_exc()}"
        add_execution_log(error_message)
        send_error_email(sns_topic_arn, "Error During Failover", error_message)

def start_instance_with_retries(instance_id, instance_name, max_retries=MAX_RETRIES, delay=DELAY_SECONDS, test_mode=False, test_data=None):
    """
    Attempts to start an instance with retries. If InsufficientInstanceCapacity error occurs,
    it retries up to max_retries times with delay between retries.
    """
    for attempt in range(1, max_retries + 1):
        try:
            add_execution_log(f"Attempt {attempt}: Starting instance {instance_name} ({instance_id}).")
            if test_mode and test_data and test_data.get('simulate_capacity_error', False):
                # Simulate InsufficientInstanceCapacity error
                raise ClientError(
                    {
                        'Error': {
                            'Code': 'InsufficientInstanceCapacity',
                            'Message': 'Simulated capacity error for testing.'
                        }
                    },
                    'StartInstances'
                )
            else:
                ec2.start_instances(InstanceIds=[instance_id])
            add_execution_log(f"Instance {instance_name} ({instance_id}) started successfully.")
            return
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InsufficientInstanceCapacity':
                add_execution_log(f"Attempt {attempt}: Insufficient capacity to start instance {instance_name}.")
                if attempt < max_retries:
                    add_execution_log(f"Waiting for {delay} seconds before retrying...")
                    time.sleep(delay)
                else:
                    add_execution_log(f"Max retries reached ({max_retries}) for starting instance {instance_name}.")
                    raise e  # Raise the exception after max retries
            else:
                add_execution_log(f"Error starting instance {instance_name}: {str(e)}")
                raise e

def manage_alarms_for_instance(instance_id, instance_name):
    """
    Manages alarms for the instance:
    - Disables alarms for all other instances.
    - Ensures alarms for the current instance are updated, enabled, and states are reset.
    """
    # Disable alarms for all other instances
    disable_alarms_for_other_instances(instance_name)

    # Always create or update alarms to reflect current constants
    create_or_update_alarms_for_instance(instance_id, instance_name)

    # Enable alarms
    enable_alarms_for_instance(instance_name)
    add_execution_log(f"Alarms enabled for instance {instance_name}.")

def disable_alarms_for_instance(instance_name):
    """
    Disables alarms associated with the given instance name by updating their configuration.
    """
    try:
        alarm_names = get_alarm_names_for_instance(instance_name)
        if alarm_names:
            for alarm_name in alarm_names:
                # Retrieve the current alarm configuration
                response = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
                alarms = response.get('MetricAlarms', [])
                if alarms:
                    alarm = alarms[0]
                    # Build parameters for put_metric_alarm
                    params = build_alarm_parameters(alarm)
                    # Update the alarm to set ActionsEnabled to False
                    params['ActionsEnabled'] = False
                    # Set TreatMissingData to 'notBreaching' to prevent alarm state changes based on missing data
                    params['TreatMissingData'] = 'notBreaching'
                    # Remove 'AlarmActionsSuppressed' if present
                    if 'AlarmActionsSuppressed' in params:
                        del params['AlarmActionsSuppressed']
                    cloudwatch.put_metric_alarm(**params)
                    # Reset the alarm state to 'OK' to prevent it from remaining in 'ALARM' state
                    cloudwatch.set_alarm_state(
                        AlarmName=alarm_name,
                        StateValue='OK',
                        StateReason='Disabling alarm and resetting state to OK due to instance scaling.'
                    )
            add_execution_log(f"Disabled alarms for instance {instance_name}: {alarm_names}")
        else:
            add_execution_log(f"No alarms found to disable for instance {instance_name}")
    except Exception as e:
        add_execution_log(f"Error disabling alarms for instance {instance_name}: {str(e)}")

def enable_alarms_for_instance(instance_name):
    """
    Enables alarms associated with the given instance name by updating their configuration.
    """
    try:
        alarm_names = get_alarm_names_for_instance(instance_name)
        if alarm_names:
            for alarm_name in alarm_names:
                # Retrieve the current alarm configuration
                response = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
                alarms = response.get('MetricAlarms', [])
                if alarms:
                    alarm = alarms[0]
                    # Build parameters for put_metric_alarm
                    params = build_alarm_parameters(alarm)
                    # Update the alarm to set ActionsEnabled to True
                    params['ActionsEnabled'] = True
                    # Set TreatMissingData to 'notBreaching' or as per configuration
                    params['TreatMissingData'] = 'notBreaching'
                    # Remove 'AlarmActionsSuppressed' if present
                    if 'AlarmActionsSuppressed' in params:
                        del params['AlarmActionsSuppressed']
                    cloudwatch.put_metric_alarm(**params)
                    # Reset the alarm state to 'INSUFFICIENT_DATA' to start fresh
                    cloudwatch.set_alarm_state(
                        AlarmName=alarm_name,
                        StateValue='INSUFFICIENT_DATA',
                        StateReason='Enabling alarm and resetting state to INSUFFICIENT_DATA due to instance scaling.'
                    )
            add_execution_log(f"Enabled alarms for instance {instance_name}: {alarm_names}")
        else:
            add_execution_log(f"No alarms found to enable for instance {instance_name}")
    except Exception as e:
        add_execution_log(f"Error enabling alarms for instance {instance_name}: {str(e)}")

def build_alarm_parameters(alarm, instance_id=None):
    """
    Builds a dictionary of parameters for put_metric_alarm, excluding None values.
    If instance_id is provided, updates the alarm parameters to match current constants.
    """
    params = {
        'AlarmName': alarm['AlarmName'],
        'AlarmDescription': alarm.get('AlarmDescription', ''),
        'ActionsEnabled': alarm['ActionsEnabled'],
        'MetricName': alarm['MetricName'],
        'Namespace': alarm['Namespace'],
        'Dimensions': alarm.get('Dimensions', []),
        'Period': alarm['Period'],
        'EvaluationPeriods': alarm['EvaluationPeriods'],
        'Threshold': alarm['Threshold'],
        'ComparisonOperator': alarm['ComparisonOperator'],
    }

    # Optional parameters
    optional_fields = [
        'Statistic',
        'ExtendedStatistic',
        'TreatMissingData',
        'EvaluateLowSampleCountPercentile',
        'AlarmActions',
        'OKActions',
        'InsufficientDataActions',
        'Unit',
        'DatapointsToAlarm',
    ]

    # Add only non-None values
    for field in optional_fields:
        value = alarm.get(field)
        if value is not None:
            params[field] = value

    # If instance_id is provided, update the parameters
    if instance_id:
        # Update thresholds and periods based on constants
        if 'CPU-High' in alarm['AlarmName']:
            cpu_threshold = CPU_UP_THRESHOLD
            cpu_up_period = calculate_alarm_period(CPU_UP_DURATION)
            cpu_up_evaluation_periods = max(1, CPU_UP_DURATION // cpu_up_period)
            cpu_up_datapoints_to_alarm = cpu_up_evaluation_periods

            params['Threshold'] = cpu_threshold
            params['Period'] = cpu_up_period
            params['EvaluationPeriods'] = cpu_up_evaluation_periods
            params['DatapointsToAlarm'] = cpu_up_datapoints_to_alarm
        elif 'CPU-Low' in alarm['AlarmName']:
            cpu_down_threshold = CPU_DOWN_THRESHOLD
            cpu_down_period = calculate_alarm_period(CPU_DOWN_DURATION)
            cpu_down_evaluation_periods = max(1, CPU_DOWN_DURATION // cpu_down_period)
            cpu_down_datapoints_to_alarm = cpu_down_evaluation_periods

            params['Threshold'] = cpu_down_threshold
            params['Period'] = cpu_down_period
            params['EvaluationPeriods'] = cpu_down_evaluation_periods
            params['DatapointsToAlarm'] = cpu_down_evaluation_periods

        # Update dimensions
        params['Dimensions'] = [{'Name': 'InstanceId', 'Value': instance_id}]

    return params

def disable_alarms_for_other_instances(active_instance_name):
    """
    Disables alarms for all instances except the active instance.
    """
    try:
        for instance in INSTANCE_SCALE_SEQUENCE:
            instance_name = instance['Name']
            if instance_name != active_instance_name:
                disable_alarms_for_instance(instance_name)
    except Exception as e:
        add_execution_log(f"Error disabling alarms for other instances: {str(e)}")

def create_or_update_alarms_for_instance(instance_id, instance_name):
    """
    Creates or updates CPU (and memory if enabled) utilization alarms for the instance.
    """
    # Retrieve the Lambda function ARN
    function_arn = LAMBDA_FUNCTION_ARN

    # Determine if scaling up is possible
    scaling_up_possible = get_next_instance_name(instance_name, direction='up') is not None

    # Determine if scaling down is possible
    scaling_down_possible = get_next_instance_name(instance_name, direction='down', levels=SCALE_DOWN_LEVELS) is not None

    # List of alarms to create or update
    alarms_to_manage = []

    # CPU High Alarm (Scaling Up)
    if scaling_up_possible:
        cpu_up_period = calculate_alarm_period(CPU_UP_DURATION)
        cpu_up_evaluation_periods = max(1, CPU_UP_DURATION // cpu_up_period)
        cpu_up_datapoints_to_alarm = cpu_up_evaluation_periods

        alarm_name = f"{ALARM_NAME_PREFIX}-{instance_name}-CPU-High"
        alarms_to_manage.append({
            'AlarmName': alarm_name,
            'MetricName': CPU_METRIC_NAME,
            'Namespace': CW_NAMESPACE,
            'Threshold': CPU_UP_THRESHOLD,
            'ComparisonOperator': 'GreaterThanThreshold',
            'Period': cpu_up_period,
            'EvaluationPeriods': cpu_up_evaluation_periods,
            'DatapointsToAlarm': cpu_up_datapoints_to_alarm,
            'Statistic': 'Average',
            'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}],
            'AlarmDescription': 'High CPU utilization',
        })

        # Memory High Alarm (Scaling Up) if memory metrics are enabled
        if USE_MEMORY_METRICS == 'Y':
            memory_up_period = calculate_alarm_period(CPU_UP_DURATION)
            memory_up_evaluation_periods = max(1, CPU_UP_DURATION // memory_up_period)
            memory_up_datapoints_to_alarm = memory_up_evaluation_periods

            alarm_name = f"{ALARM_NAME_PREFIX}-{instance_name}-Memory-High"
            alarms_to_manage.append({
                'AlarmName': alarm_name,
                'MetricName': MEMORY_METRIC_NAME,
                'Namespace': 'CWAgent',
                'Threshold': MEMORY_UP_THRESHOLD,
                'ComparisonOperator': 'GreaterThanThreshold',
                'Period': memory_up_period,
                'EvaluationPeriods': memory_up_evaluation_periods,
                'DatapointsToAlarm': memory_up_datapoints_to_alarm,
                'Statistic': 'Average',
                'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}],
                'AlarmDescription': 'High Memory utilization',
            })

    # CPU Low Alarm (Scaling Down), but not for smallest instances
    if scaling_down_possible and instance_name not in SMALLEST_INSTANCES:
        cpu_down_period = calculate_alarm_period(CPU_DOWN_DURATION)
        cpu_down_evaluation_periods = max(1, CPU_DOWN_DURATION // cpu_down_period)
        cpu_down_datapoints_to_alarm = cpu_down_evaluation_periods

        alarm_name = f"{ALARM_NAME_PREFIX}-{instance_name}-CPU-Low"
        alarms_to_manage.append({
            'AlarmName': alarm_name,
            'MetricName': CPU_METRIC_NAME,
            'Namespace': CW_NAMESPACE,
            'Threshold': CPU_DOWN_THRESHOLD,
            'ComparisonOperator': 'LessThanThreshold',
            'Period': cpu_down_period,
            'EvaluationPeriods': cpu_down_evaluation_periods,
            'DatapointsToAlarm': cpu_down_evaluation_periods,
            'Statistic': 'Average',
            'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}],
            'AlarmDescription': 'Low CPU utilization',
        })

    # Create or update alarms
    for alarm_config in alarms_to_manage:
        try:
            # Check if the alarm exists
            response = cloudwatch.describe_alarms(AlarmNames=[alarm_config['AlarmName']])
            if response['MetricAlarms']:
                # Alarm exists, update it
                add_execution_log(f"Updating alarm {alarm_config['AlarmName']} for instance {instance_name}.")
            else:
                # Alarm does not exist, create it
                add_execution_log(f"Creating alarm {alarm_config['AlarmName']} for instance {instance_name}.")

            # Common alarm parameters
            alarm_params = {
                'AlarmName': alarm_config['AlarmName'],
                'AlarmDescription': alarm_config['AlarmDescription'],
                'ActionsEnabled': True,
                'AlarmActions': [function_arn],
                'MetricName': alarm_config['MetricName'],
                'Namespace': alarm_config['Namespace'],
                'Statistic': alarm_config['Statistic'],
                'Dimensions': alarm_config['Dimensions'],
                'Period': alarm_config['Period'],
                'EvaluationPeriods': alarm_config['EvaluationPeriods'],
                'DatapointsToAlarm': alarm_config['DatapointsToAlarm'],
                'Threshold': alarm_config['Threshold'],
                'ComparisonOperator': alarm_config['ComparisonOperator'],
                'TreatMissingData': 'notBreaching',
            }

            cloudwatch.put_metric_alarm(**alarm_params)
        except Exception as e:
            add_execution_log(f"Error creating or updating alarm {alarm_config['AlarmName']}: {str(e)}")

    # Add permission for CloudWatch to invoke the Lambda function
    add_lambda_permission_for_cloudwatch(function_arn)

def calculate_alarm_period(duration_seconds):
    """
    Calculates the appropriate alarm period based on the duration and data availability.
    """
    # For basic monitoring, data is available every 300 seconds (5 minutes)
    # For detailed monitoring, data is available every 60 seconds (1 minute)
    # Adjust the period to match data availability and evenly divide into duration
    # Default to 300 seconds (5 minutes) for compatibility with basic monitoring
    period = 300  # Default period

    # Ensure that duration is evenly divisible by period
    while duration_seconds % period != 0 and period > 1:
        period -= 1  # Reduce period to find a divisor

    return period

def add_lambda_permission_for_cloudwatch(function_arn):
    """
    Adds permission to the Lambda function to allow CloudWatch to invoke it.
    """
    try:
        lambda_client.add_permission(
            FunctionName=function_arn,
            StatementId='AllowCloudWatchAlarmInvocationRON',
            Action='lambda:InvokeFunction',
            Principal='cloudwatch.amazonaws.com',
            SourceArn=f"arn:aws:cloudwatch:{AWS_REGION}:{ACCOUNT_ID}:alarm/*"
        )
        add_execution_log("Added permission to Lambda function for CloudWatch alarms.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            add_execution_log("Permission already exists for CloudWatch alarms.")
        else:
            add_execution_log(f"Error adding permission to Lambda function for CloudWatch alarms: {str(e)}")

def get_instance_id_by_name_tag(name_tag_value):
    """
    Retrieves the instance ID of an EC2 instance based on the 'Name' tag value.
    """
    try:
        response = ec2.describe_instances(
            Filters=[
                {'Name': f'tag:{EC2_NAME_TAG_KEY}', 'Values': [name_tag_value]},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
            ]
        )
        reservations = response['Reservations']
        if reservations:
            for reservation in reservations:
                instances = reservation['Instances']
                if instances:
                    instance_id = instances[0]['InstanceId']
                    add_execution_log(f"Found instance ID {instance_id} for tag 'Name' = '{name_tag_value}'")
                    return instance_id
        add_execution_log(f"No instance found with tag 'Name' = '{name_tag_value}'")
        return None
    except Exception as e:
        add_execution_log(f"Error retrieving instance ID by tag 'Name' = '{name_tag_value}': {str(e)}")
        return None

def get_all_instance_ids():
    """
    Retrieves all instance IDs involved in the scaling sequence.
    """
    instance_ids = []
    try:
        instance_names = [inst['Name'] for inst in INSTANCE_SCALE_SEQUENCE]
        response = ec2.describe_instances(
            Filters=[
                {'Name': f'tag:{EC2_NAME_TAG_KEY}', 'Values': instance_names},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
            ]
        )
        reservations = response['Reservations']
        for reservation in reservations:
            instances = reservation['Instances']
            for instance in instances:
                instance_ids.append(instance['InstanceId'])
        return instance_ids
    except Exception as e:
        add_execution_log(f"Error retrieving all instance IDs: {str(e)}")
        return instance_ids

def get_instance_state(instance_id):
    """
    Retrieves the state of an EC2 instance.
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        state = response['Reservations'][0]['Instances'][0]['State']['Name']
        add_execution_log(f"Instance {instance_id} state: {state}")
        return state
    except Exception as e:
        add_execution_log(f"Error retrieving state for instance {instance_id}: {str(e)}")
        return None

def get_attached_volume(instance_id):
    """
    Retrieves the volume ID and device name of the volume attached to the instance.
    """
    try:
        response = ec2.describe_volumes(
            Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
        )
        volumes = response['Volumes']
        if volumes:
            # Find the root volume
            for volume in volumes:
                for attachment in volume['Attachments']:
                    if attachment['InstanceId'] == instance_id and attachment['Device'] in ['/dev/xvda', '/dev/sda1']:
                        volume_id = volume['VolumeId']
                        device_name = attachment['Device']
                        add_execution_log(f"Found volume {volume_id} attached to instance {instance_id} at device {device_name}")
                        return volume_id, device_name
            add_execution_log(f"No root volume found attached to instance {instance_id}")
            return None, None
        else:
            add_execution_log(f"No volumes found attached to instance {instance_id}")
            return None, None
    except Exception as e:
        add_execution_log(f"Error retrieving attached volume for instance {instance_id}: {str(e)}")
        return None, None

def create_and_tag_snapshot(volume_id, snapshot_name):
    """
    Creates a snapshot of the given volume and tags it. Deletes old snapshots with the same name.
    Returns the new snapshot ID.
    """
    # Delete old snapshots with the same name
    old_snapshots = delete_old_snapshots(snapshot_name)
    if old_snapshots:
        add_execution_log(f"Deleted old snapshot(s): {', '.join(old_snapshots)} with name '{snapshot_name}'")
    else:
        add_execution_log(f"No old snapshots found with name '{snapshot_name}'")

    # Create a new snapshot
    add_execution_log(f"Creating snapshot for volume {volume_id}")
    try:
        snapshot = retry_with_backoff(lambda: ec2.create_snapshot(
            VolumeId=volume_id,
            Description="Backup snapshot before volume switch",
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [{'Key': 'Name', 'Value': snapshot_name}]}]
        ))
        snapshot_id = snapshot['SnapshotId']
        add_execution_log(f"Snapshot creation initiated: {snapshot_id}")
        return snapshot_id
    except Exception as e:
        add_execution_log(f"Error creating snapshot for volume {volume_id}: {str(e)}")
        return None

def wait_for_snapshot_completion(snapshot_id):
    """
    Waits for the snapshot to complete and verifies its state.
    Returns True if successful, False otherwise.
    """
    try:
        add_execution_log(f"Waiting for snapshot {snapshot_id} to be completed")
        max_retries = MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
        delay = DELAY_SECONDS
        for attempt in range(max_retries):
            try:
                response = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
                snapshot = response['Snapshots'][0]
                state = snapshot['State']
                if state == 'completed':
                    add_execution_log(f"Snapshot {snapshot_id} is completed successfully.")
                    return True
                elif state == 'error':
                    add_execution_log(f"Snapshot {snapshot_id} encountered an error. State: {state}")
                    return False
                else:
                    add_execution_log(f"Snapshot {snapshot_id} is in state '{state}'. Waiting...")
            except botocore.exceptions.ClientError as e:
                if 'InvalidSnapshot.NotFound' in str(e):
                    add_execution_log(f"Snapshot {snapshot_id} not found. Retrying...")
                else:
                    raise e
            time.sleep(delay)
        add_execution_log(f"Snapshot {snapshot_id} did not complete within the allowed time.")
        return False
    except Exception as e:
        add_execution_log(f"Error waiting for snapshot {snapshot_id} to complete: {str(e)}")
        return False

def wait_for_users(wait_time):
    """
    Waits for the specified amount of time to allow users to wrap up their work.
    """
    add_execution_log(f"Waiting for {wait_time} seconds to allow users to stop their work.")
    time.sleep(wait_time)
    add_execution_log("Proceeding after user waiting period.")

def attach_volume_to_target_instance(target_instance_id, volume_id):
    """
    Attaches the given volume to the target instance as the root device.
    """
    # Detach existing root volume if it exists
    add_execution_log(f"Checking for existing root volume on instance {target_instance_id}.")
    root_volume_id = get_root_volume(target_instance_id)
    if root_volume_id:
        add_execution_log(f"Detaching existing root volume {root_volume_id} from instance {target_instance_id}")
        if ensure_volume_is_attached(root_volume_id, target_instance_id):
            retry_with_backoff(lambda: ec2.detach_volume(VolumeId=root_volume_id, InstanceId=target_instance_id, Force=True))
            # Wait until the root volume is detached with timeout
            add_execution_log(f"Waiting for existing root volume {root_volume_id} to become available.")
            waiter = ec2.get_waiter('volume_available')
            waiter.wait(
                VolumeIds=[root_volume_id],
                WaiterConfig={
                    'Delay': DELAY_SECONDS,
                    'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
                }
            )
        else:
            add_execution_log(f"Root volume {root_volume_id} is not attached to instance {target_instance_id}. Skipping detachment.")

    # Attach the new volume as root
    root_device_name = '/dev/xvda'  # Default root device name
    add_execution_log(f"Attaching volume {volume_id} to instance {target_instance_id} at root device {root_device_name}")
    retry_with_backoff(lambda: ec2.attach_volume(InstanceId=target_instance_id, VolumeId=volume_id, Device=root_device_name))

    # Wait until the volume is attached with timeout
    add_execution_log(f"Waiting for volume {volume_id} to be attached to instance {target_instance_id}")
    waiter = ec2.get_waiter('volume_in_use')
    waiter.wait(
        VolumeIds=[volume_id],
        WaiterConfig={
            'Delay': DELAY_SECONDS,
            'MaxAttempts': MAX_ATTEMPTS  # Wait up to DELAY_SECONDS * MAX_ATTEMPTS seconds
        }
    )

def ensure_volume_is_attached(volume_id, instance_id):
    """
    Checks if the volume is attached to the given instance.
    Returns True if attached, False if already detached or in 'available' state.
    """
    try:
        response = ec2.describe_volumes(VolumeIds=[volume_id])
        volume = response['Volumes'][0]
        state = volume['State']
        attachments = volume.get('Attachments', [])

        if state == 'available':
            add_execution_log(f"Volume {volume_id} is already in 'available' state. No detachment needed.")
            return False  # No detachment required
        elif state == 'in-use' and any(attachment['InstanceId'] == instance_id for attachment in attachments):
            return True  # Volume is attached and ready to be detached
        else:
            add_execution_log(f"Volume {volume_id} is in state '{state}' and not attached to instance {instance_id}.")
            return False
    except Exception as e:
        add_execution_log(f"Error checking volume state for {volume_id}: {str(e)}")
        return False

def get_root_volume(instance_id):
    """
    Retrieves the root volume ID of an EC2 instance.
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        block_device_mappings = response['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', [])
        root_device_name = response['Reservations'][0]['Instances'][0].get('RootDeviceName', '/dev/xvda')
        for bdm in block_device_mappings:
            if bdm['DeviceName'] == root_device_name:
                volume_id = bdm['Ebs']['VolumeId']
                return volume_id
        return None
    except Exception as e:
        add_execution_log(f"Error retrieving root volume for instance {instance_id}: {str(e)}")
        return None

def get_elastic_ip_allocation_by_name_tag(name_tag_value):
    """
    Retrieves the allocation ID of an Elastic IP based on the 'Name' tag value.
    """
    try:
        response = ec2.describe_addresses(
            Filters=[
                {'Name': 'tag:Name', 'Values': [name_tag_value]}
            ]
        )
        addresses = response['Addresses']
        if addresses:
            allocation_id = addresses[0]['AllocationId']
            add_execution_log(f"Found Elastic IP allocation ID {allocation_id} for tag 'Name' = '{name_tag_value}'")
            return allocation_id
        else:
            add_execution_log(f"No Elastic IP found with tag 'Name' = '{name_tag_value}'")
            return None
    except Exception as e:
        add_execution_log(f"Error retrieving Elastic IP by tag 'Name' = '{name_tag_value}': {str(e)}")
        return None

def get_sns_topic_arn_by_tag(tag_key, tag_value):
    """
    Retrieves the SNS topic ARN based on a tag key and value.
    """
    try:
        # List all SNS topics
        topics = []
        next_token = ''
        while True:
            if next_token:
                response = sns.list_topics(NextToken=next_token)
            else:
                response = sns.list_topics()
            topics.extend(response.get('Topics', []))
            next_token = response.get('NextToken', '')
            if not next_token:
                break

        # Check each topic's tags
        for topic in topics:
            topic_arn = topic['TopicArn']
            tags_response = sns.list_tags_for_resource(ResourceArn=topic_arn)
            tags = tags_response.get('Tags', [])
            for tag in tags:
                if tag['Key'] == tag_key and tag['Value'] == tag_value:
                    add_execution_log(f"Found SNS topic ARN {topic_arn} with tag '{tag_key}' = '{tag_value}'")
                    return topic_arn
        add_execution_log(f"No SNS topic found with tag '{tag_key}' = '{tag_value}'")
        return None
    except Exception as e:
        add_execution_log(f"Error retrieving SNS topic ARN by tag '{tag_key}' = '{tag_value}': {str(e)}")
        return None

def retry_with_backoff(func, max_retries=MAX_RETRIES):
    """
    Retries a function with exponential backoff in case of retriable ClientError exceptions.
    If retries exceed 2 attempts, sends an immediate email with error details.
    """
    retriable_errors = ['RequestLimitExceeded', 'Throttling', 'InternalError']
    for i in range(max_retries):
        try:
            return func()
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in retriable_errors:
                if i < max_retries - 1:
                    delay = 2 ** i + random.uniform(0, 1)
                    add_execution_log(f"Attempt {i + 1} failed with {error_code}: {str(e)}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    error_message = f"Max retries reached. Function failed with error: {str(e)}"
                    add_execution_log(error_message)
                    if i >= 2 and sns_topic_arn_global:
                        send_error_email(sns_topic_arn_global, "Error After Multiple Retries", error_message)
                    raise
            else:
                error_message = f"Non-retriable error: {str(e)}"
                add_execution_log(error_message)
                if i >= 2 and sns_topic_arn_global:
                    send_error_email(sns_topic_arn_global, "Error After Multiple Retries", error_message)
                raise
        except botocore.exceptions.WaiterError as e:
            if i < max_retries - 1:
                delay = 2 ** i + random.uniform(0, 1)
                add_execution_log(f"Waiter attempt {i + 1} failed: {str(e)}. Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                error_message = f"Max retries reached for waiter. Function failed with error: {str(e)}"
                add_execution_log(error_message)
                if i >= 2 and sns_topic_arn_global:
                    send_error_email(sns_topic_arn_global, "Error After Multiple Retries", error_message)
                raise

def delete_old_snapshots(snapshot_name):
    """
    Deletes old snapshots with the given name tag.
    Returns the list of deleted snapshot IDs.
    """
    try:
        response = ec2.describe_snapshots(
            Filters=[
                {'Name': 'tag:Name', 'Values': [snapshot_name]},
                {'Name': 'owner-id', 'Values': [ACCOUNT_ID]}
            ]
        )
        snapshots = response['Snapshots']
        if snapshots:
            deleted_snapshot_ids = []
            for snapshot in snapshots:
                snapshot_id = snapshot['SnapshotId']
                add_execution_log(f"Deleting old snapshot {snapshot_id} with name '{snapshot_name}'")
                retry_with_backoff(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
                deleted_snapshot_ids.append(snapshot_id)
            return deleted_snapshot_ids
        else:
            add_execution_log(f"No old snapshots found with name '{snapshot_name}'")
            return None
    except Exception as e:
        add_execution_log(f"Error deleting old snapshots with name '{snapshot_name}': {str(e)}")
        return None

def get_snapshot_state(snapshot_id):
    """
    Retrieves the state of the snapshot.
    """
    try:
        response = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
        snapshot = response['Snapshots'][0]
        state = snapshot['State']
        return state
    except Exception as e:
        add_execution_log(f"Error retrieving state for snapshot {snapshot_id}: {str(e)}")
        return None

def tag_instance_as_last_used(instance_id, all_instance_ids):
    """
    Tags the specified instance as 'LastUsed' and removes the tag from other instances.
    """
    try:
        # Remove 'LastUsed' tag from all instances
        ec2.delete_tags(
            Resources=all_instance_ids,
            Tags=[{'Key': 'LastUsed'}]
        )
        # Tag the target instance
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'LastUsed', 'Value': 'true'}]
        )
        add_execution_log(f"Instance {instance_id} tagged as 'LastUsed'.")
    except ClientError as e:
        add_execution_log(f"Error tagging instance {instance_id}: {e.response['Error']['Message']}")

# ====================================================================
# Additional Helper Function to Get Instance Name from Alarm
# ====================================================================

def get_alarm_names_for_instance(instance_name):
    """
    Retrieves the names of alarms associated with the given instance name.
    """
    try:
        paginator = cloudwatch.get_paginator('describe_alarms')
        alarm_names = []
        for page in paginator.paginate(AlarmNamePrefix=f"{ALARM_NAME_PREFIX}-{instance_name}"):
            alarms = page.get('MetricAlarms', [])
            for alarm in alarms:
                alarm_names.append(alarm['AlarmName'])
        return alarm_names
    except Exception as e:
        add_execution_log(f"Error retrieving alarms for instance {instance_name}: {str(e)}")
        return []

def get_instance_name_from_alarm(alarm_name):
    """
    Extracts the instance name from the alarm name.
    Assumes the alarm name is in the format: ALARM_NAME_PREFIX-instance_name-alarm_type
    """
    try:
        parts = alarm_name.split('-')
        if len(parts) >= 3:
            instance_name = '-'.join(parts[1:-1])  # Handles instance names with hyphens
            return instance_name
        else:
            return None
    except Exception as e:
        add_execution_log(f"Error extracting instance name from alarm name {alarm_name}: {str(e)}")
        return None

# ====================================================================
# End of Lambda Function Code
# ====================================================================
