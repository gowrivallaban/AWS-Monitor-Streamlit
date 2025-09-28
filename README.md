# AWS Service Status Dashboard

A simple Streamlit-based dashboard to monitor AWS service status using the AWS Health API.

## Features

- Real-time monitoring of AWS service status
- Displays active issues and scheduled maintenance
- Shows affected regions and services
- User-friendly interface with refresh capability

## Prerequisites

- Python 3.8+
- AWS account with appropriate IAM permissions
- AWS Access Key ID and Secret Access Key with `health:DescribeEvents` permission

## Setup

1. Clone this repository
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the project root and add your AWS credentials:
   ```
   AWS_ACCESS_KEY_ID=your_access_key_here
   AWS_SECRET_ACCESS_KEY=your_secret_key_here
   ```

## Running the Dashboard

1. Start the Streamlit app:
   ```bash
   streamlit run aws_status_dashboard.py
   ```
2. Open your browser and navigate to the URL shown in the terminal (usually http://localhost:8501)

## IAM Permissions

Ensure your AWS IAM user has the following permissions:
- `health:DescribeEvents`
- `health:DescribeEventDetails`
- `health:DescribeAffectedEntities`

## Security Note

Never commit your `.env` file or share your AWS credentials. The `.env` file is included in `.gitignore` to prevent accidental commits.
