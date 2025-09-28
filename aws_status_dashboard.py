import streamlit as st
import pandas as pd
import feedparser
from datetime import datetime, timezone
import re
import os
from dotenv import load_dotenv
import boto3
from botocore.client import BaseClient
from typing import Dict, List, Any, Optional
import concurrent.futures
from collections import defaultdict

# Load environment variables
load_dotenv()

# Set page config
st.set_page_config(
    page_title="AWS Service Status Dashboard",
    page_icon="☁️",
    layout="wide"
)

# --- AWS Service Discovery ---
def get_aws_credentials() -> bool:
    """Check for AWS credentials."""
    return bool(os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'))

def get_available_regions(service_name: str = 'ec2') -> List[str]:
    """Get list of available AWS regions for a given service."""
    session = boto3.Session(
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    return session.get_available_regions(service_name)

def get_aws_resources() -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Discover all AWS resources across all regions and services."""
    resources = defaultdict(lambda: defaultdict(list))
    
    # Get all available regions
    regions = get_available_regions()
    
    # List of services to scan
    services = [
        'acm', 'apigateway', 'appstream', 'appsync', 'athena', 'autoscaling',
        'backup', 'batch', 'cloudformation', 'cloudfront', 'cloudhsmv2', 'cloudsearch',
        'cloudtrail', 'cloudwatch', 'codebuild', 'codecommit', 'codedeploy', 'codepipeline',
        'cognito-identity', 'cognito-idp', 'config', 'datapipeline', 'datasync', 'dax',
        'directconnect', 'dms', 'docdb', 'dynamodb', 'ebs', 'ec2', 'ecr', 'ecs', 'efs',
        'eks', 'elasticache', 'elasticbeanstalk', 'elb', 'elbv2', 'emr', 'es', 'events',
        'firehose', 'fsx', 'glacier', 'glue', 'guardduty', 'iam', 'inspector', 'iot',
        'kafka', 'kinesis', 'kinesisanalytics', 'kinesisvideo', 'kms', 'lambda',
        'logs', 'mediaconnect', 'mediaconvert', 'medialive', 'mediapackage', 'mediastore',
        'mq', 'neptune', 'opensearch', 'qldb', 'rds', 'redshift', 'route53', 'route53domains',
        'route53resolver', 's3', 'sagemaker', 'secretsmanager', 'securityhub', 'serverlessrepo',
        'servicecatalog', 'ses', 'sns', 'sqs', 'ssm', 'stepfunctions', 'storagegateway',
        'waf', 'waf-regional', 'wafv2', 'workspaces', 'xray'
    ]
    
    def process_region(service_name: str, region: str) -> None:
        try:
            client = boto3.client(
                service_name,
                region_name=region,
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
            )
            
            # Special handling for global services
            if service_name in ['iam', 'route53', 'cloudfront'] and region != 'us-east-1':
                return
                
            # Try to list resources based on service type
            try:
                if service_name == 's3':
                    response = client.list_buckets()
                    for bucket in response.get('Buckets', []):
                        resources[service_name][region].append({
                            'Name': bucket['Name'],
                            'Type': 'Bucket',
                            'ARN': f"arn:aws:s3:::{bucket['Name']}"
                        })
                
                elif service_name == 'ec2':
                    # EC2 Instances
                    instances = client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
                    for reservation in instances.get('Reservations', []):
                        for instance in reservation.get('Instances', []):
                            resources[service_name][region].append({
                                'Name': next((tag['Value'] for tag in instance.get('Tags', []) 
                                            if tag.get('Key') == 'Name'), instance['InstanceId']),
                                'Type': 'EC2 Instance',
                                'ARN': f"arn:aws:ec2:{region}:{instance.get('OwnerId', '')}:instance/{instance['InstanceId']}"
                            })
                    
                    # VPCs
                    vpcs = client.describe_vpcs()
                    for vpc in vpcs.get('Vpcs', []):
                        resources['vpc'][region].append({
                            'Name': next((tag['Value'] for tag in vpc.get('Tags', []) 
                                         if tag.get('Key') == 'Name'), vpc['VpcId']),
                            'Type': 'VPC',
                            'ARN': f"arn:aws:ec2:{region}:{vpc.get('OwnerId', '')}:vpc/{vpc['VpcId']}"
                        })
                
                elif service_name == 'rds':
                    instances = client.describe_db_instances()
                    for db in instances.get('DBInstances', []):
                        resources[service_name][region].append({
                            'Name': db['DBInstanceIdentifier'],
                            'Type': 'RDS Instance',
                            'ARN': db.get('DBInstanceArn', '')
                        })
                
                elif service_name == 'lambda':
                    functions = client.list_functions()
                    for func in functions.get('Functions', []):
                        resources[service_name][region].append({
                            'Name': func['FunctionName'],
                            'Type': 'Lambda Function',
                            'ARN': func['FunctionArn']
                        })
                
                # Add more service-specific handling as needed
                
                # Generic list_resources for services that support it
                elif 'list_' in dir(client):
                    try:
                        paginator = client.get_paginator('list_resources')
                        for page in paginator.paginate():
                            for resource in page.get('ResourceIdentifiers', []):
                                resources[service_name][region].append({
                                    'Name': resource.get('ResourceName', resource.get('ResourceId', 'Unnamed')),
                                    'Type': service_name.upper(),
                                    'ARN': resource.get('ResourceARN', '')
                                })
                    except:
                        pass
                        
            except Exception as e:
                # Skip services that don't support listing or require special permissions
                pass
                
        except Exception as e:
            # Skip regions where the service is not available
            pass
    
    # Use ThreadPoolExecutor to speed up the discovery
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for service in services:
            for region in regions:
                futures.append(executor.submit(process_region, service, region))
        
        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                continue
    
    return resources

# URL for the AWS status RSS feed
AWS_STATUS_RSS_URL = "http://status.aws.amazon.com/rss/all.rss"

def get_aws_status_from_rss():
    """Fetch AWS service health status from the public RSS feed."""
    columns=['Service', 'Title', 'Published', 'Description', 'Status']
    try:
        feed = feedparser.parse(AWS_STATUS_RSS_URL)
        if feed.bozo:
            st.warning("Warning: RSS feed may be malformed.")

        events = []
        for entry in feed.entries:
            title = entry.title
            # More robustly extract service name
            service_match = re.search(r'Service(?: Disruption| Update): (.*?)(?: \(|for)', title)
            if not service_match:
                service_match = re.search(r'\((.*?)\)', title)
            
            service = service_match.group(1).strip() if service_match else 'General'

            # Determine status based on keywords
            if 'resolved' in title.lower() or 'completed' in title.lower():
                status = 'Operating Normally'
            else:
                status = 'Service Disruption'

            events.append({
                'Service': service,
                'Title': title,
                'Published': entry.published,
                'Description': entry.description,
                'Status': status
            })
        
        return pd.DataFrame(events, columns=columns)
    except Exception as e:
        st.error(f"Error fetching AWS Health data from RSS feed: {str(e)}")
        return pd.DataFrame(columns=columns)

# A list of common AWS services
AWS_SERVICES = [
    "EC2", "S3", "RDS", "Lambda", "IAM", "VPC", "Route53", "CloudFront",
    "DynamoDB", "SQS", "SNS", "CloudWatch", "ElasticBeanstalk", "ECS", "EKS",
    "KMS", "SecretsManager", "APIGateway", "Cognito", "ElastiCache", "OpenSearch",
    "Redshift", "Glue", "Athena", "Kinesis", "SageMaker", "Translate", "Polly",
    "Rekognition", "Comprehend", "Lex"
]

def get_service_status(events_df):
    """Get the status for each AWS service from the RSS feed data."""
    service_status = {}
    # Filter for events that are not resolved
    active_events = events_df[events_df['Status'] != 'Operating Normally']

    for service in AWS_SERVICES:
        # Check if the service name appears in any of the active event titles
        service_events = active_events[active_events['Title'].str.contains(service, case=False)]
        
        if not service_events.empty:
            service_status[service] = {
                'status': 'Service Disruption',
                'events': service_events
            }
        else:
            service_status[service] = {
                'status': 'Operating Normally',
                'events': pd.DataFrame()
            }
    return service_status

def display_aws_resources(resources: Dict[str, Dict[str, List[Dict[str, Any]]]], events_df: pd.DataFrame) -> None:
    """Display AWS resources in a user-friendly format."""
    service_status = get_service_status(events_df)
    
    # Create tabs for each service
    services = sorted(resources.keys())
    if not services:
        st.warning("No AWS resources found. Please check your credentials and permissions.")
        return
    
    tabs = st.tabs([f"{s.upper()}" for s in services])
    
    for idx, (service, regions) in enumerate(sorted(resources.items())):
        with tabs[idx]:
            # Get service status from RSS feed
            status = service_status.get(service.upper(), {}).get('status', 'Unknown')
            
            # Display service status
            status_color = 'green' if status == 'Operating Normally' else 'red'
            st.markdown(f"**Status:** :{status_color}[{status}]")
            
            # Display service-specific metrics
            total_resources = sum(len(region_resources) for region_resources in regions.values())
            st.metric(f"Total {service.upper()} Resources", total_resources)
            
            # Show resources by region
            for region, region_resources in sorted(regions.items()):
                if not region_resources:
                    continue
                    
                with st.expander(f"{region} ({len(region_resources)} resources)"):
                    # Create a DataFrame for the resources in this region
                    df = pd.DataFrame(region_resources)
                    
                    # Display the resources in a table
                    st.dataframe(
                        df[['Name', 'Type', 'ARN']],
                        column_config={
                            'Name': 'Resource Name',
                            'Type': 'Resource Type',
                            'ARN': st.column_config.LinkColumn('ARN', display_text='View in Console')
                        },
                        hide_index=True,
                        use_container_width=True
                    )

def main():
    # Title and description
    st.title("☁️ AWS Resource Explorer")
    st.markdown("""
    This dashboard provides an overview of all AWS resources in your account, along with their status.
    """)
    
    # Add a refresh button
    if st.button('🔄 Refresh Resources'):
        st.rerun()
    
    # Check AWS credentials
    if not get_aws_credentials():
        st.error("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.")
        return
    
    # Get AWS status data
    with st.spinner('Fetching AWS service status from RSS feed...'):
        events_df = get_aws_status_from_rss()
    
    # Display status summary
    st.subheader("🔍 AWS Resource Summary")
    
    # Discover AWS resources
    with st.spinner('Discovering AWS resources across all regions...'):
        resources = get_aws_resources()
    
    # Display resources
    display_aws_resources(resources, events_df)
    
    # Display service health status
    st.markdown("---")
    st.subheader("🚦 AWS Service Health Status")
    
    active_issues = events_df[events_df['Status'] != 'Operating Normally']
    if not active_issues.empty:
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Active Issues", len(active_issues))
        with col2:
            st.metric("Affected Services", active_issues['Service'].nunique())
        
        st.warning("⚠️ There are active issues with some AWS services. See details below.")
    else:
        st.success("✅ All AWS services are operating normally")
        st.balloons()

    # Get service status from RSS feed
    service_status = get_service_status(events_df)
    
    # Display detailed service status
    st.markdown("### 📋 Service Status Details")
    
    # Group services by status
    status_groups = {}
    for service, data in service_status.items():
        status = data['status']
        if status not in status_groups:
            status_groups[status] = []
        status_groups[status].append((service, data))
    
    # Sort status groups (issues first, then normal)
    for status in sorted(status_groups.keys(), key=lambda x: x == 'Operating Normally'):
        services = status_groups[status]
        status_display = "🟢 Operating Normally" if status == 'Operating Normally' else f"🔴 {status}"
        
        with st.expander(f"{status_display} ({len(services)} services)"):
            for service, data in sorted(services):
                with st.container():
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        st.markdown(f"**{service}**")
                    with col2:
                        status_color = 'green' if status == 'Operating Normally' else 'red'
                        st.markdown(f":{status_color}[{status}]")
                    
                    if not data['events'].empty:
                        with st.expander("View details", expanded=False):
                            st.dataframe(
                                data['events'], 
                                hide_index=True, 
                                use_container_width=True,
                                column_config={
                                    'Title': 'Description',
                                    'Published': 'Last Updated',
                                    'Status': st.column_config.TextColumn(
                                        'Status',
                                        help='Current status of the service',
                                        width='small'
                                    )
                                }
                            )
    
    # Add a small note about when the data was last updated
    st.caption(f"Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    
    # Add some helpful links
    st.markdown("---")
    st.markdown("### 🔗 Helpful AWS Resources")
    st.markdown("""
    - [AWS Health Dashboard](https://health.aws.com/)
    - [AWS Service Health Dashboard](https://status.aws.amazon.com/)
    - [AWS Personal Health Dashboard](https://phd.aws.amazon.com/)
    """)

    # --- My AWS Resources Section ---
    st.markdown("---")
    st.subheader("💻 My AWS Resources")
    
    # Add a note about the resource discovery
    st.info("""
    ℹ️ The resource discovery process scans your AWS account for resources across all supported services and regions. 
    This may take a few moments to complete.
    """)
    
    # Add a button to refresh resources
    if st.button("🔄 Refresh Resources", key="refresh_resources"):
        st.rerun()
    
    # Check if AWS credentials are available
    if not get_aws_credentials():
        st.warning("""
        No AWS credentials found. To use this feature, please create a `.env` file with your AWS credentials:
        ```
        AWS_ACCESS_KEY_ID=your_access_key
        AWS_SECRET_ACCESS_KEY=your_secret_key
        ```
        Or set them as environment variables before running the application.
        """)
        return
    
    # Get AWS resources
    with st.spinner("Discovering AWS resources across all regions..."):
        resources = get_aws_resources()
    
    # Display resources in a tabbed interface
    if not resources:
        st.warning("No AWS resources found. Please check your credentials and permissions.")
        return
    
    # Calculate resource counts by service and region
    service_counts = {}
    for service, regions in resources.items():
        service_counts[service] = sum(len(resources) for resources in regions.values())
    
    # Display resource summary cards
    st.markdown("### 📊 Resource Summary")
    
    # Create columns for the summary cards
    cols = st.columns(4)
    total_resources = sum(service_counts.values())
    
    with cols[0]:
        st.metric("Total Services", len(service_counts))
    with cols[1]:
        st.metric("Total Resources", total_resources)
    with cols[2]:
        st.metric("Total Regions", len({region for service in resources.values() for region in service.keys()}))
    with cols[3]:
        st.metric("Last Updated", datetime.now(timezone.utc).strftime('%H:%M:%S'))
    
    # Display resources by service in tabs
    st.markdown("### 🗂️ Resources by Service")
    
    # Create tabs for each service
    services = sorted(resources.keys(), key=lambda x: -service_counts.get(x, 0))  # Sort by resource count
    tabs = st.tabs([f"{s.upper()} ({service_counts[s]})" for s in services])
    
    for idx, service in enumerate(services):
        with tabs[idx]:
            regions = resources[service]
            
            # Display service summary
            st.markdown(f"**Total Resources:** {service_counts[service]}")
            st.markdown(f"**Regions with Resources:** {len(regions)}")
            
            # Display resources by region
            for region, region_resources in sorted(regions.items()):
                if not region_resources:
                    continue
                
                with st.expander(f"{region} ({len(region_resources)} resources)", expanded=False):
                    # Create a DataFrame for the resources in this region
                    df = pd.DataFrame(region_resources)
                    
                    # Display the resources in a table
                    st.dataframe(
                        df[['Name', 'Type', 'ARN']],
                        column_config={
                            'Name': 'Resource Name',
                            'Type': 'Resource Type',
                            'ARN': st.column_config.LinkColumn('ARN', display_text='View in Console')
                        },
                        hide_index=True,
                        use_container_width=True,
                        height=min(300, 35 * (len(df) + 1))  # Adjust height based on number of rows
                    )
    
    # Add a note about permissions
    st.markdown("---")
    st.info("""
    ### 🔐 Required IAM Permissions
    To ensure all resources are discovered, your IAM user/role should have the following permissions:
    - `ec2:Describe*`
    - `s3:ListAllMyBuckets`
    - `rds:Describe*`
    - `lambda:ListFunctions`
    - And similar list/describe permissions for other AWS services
    
    For a complete list of required permissions, refer to the [AWS Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage.html).
    """)

if __name__ == "__main__":
    main()
