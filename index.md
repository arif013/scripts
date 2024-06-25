# AWS Data Perimeter Automation - Chowdhury Faizal Ahammed

i have used boto3 for iam interractions, rich for terminal logging and csv module to write the output to a csv

### The Script

```py
import boto3
import json
import csv
from rich.progress import Progress
from rich.table import Table
from rich import print
from rich.console import Console
from time import time

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession"
        )
        return assumed_role['Credentials']
    except sts_client.exceptions.ClientError as e:
        print(f"[bold red]Failed to assume role {role_name} in account {account_id}: {str(e)}[/bold red]")
        return None

def update_trust_policy(iam_client, role_name, new_trust_policy_statement):
    try:
        current_policy = iam_client.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
    except iam_client.exceptions.NoSuchEntityException:
        return False

    if new_trust_policy_statement not in current_policy['Statement']:
        current_policy['Statement'].append(new_trust_policy_statement)
        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(current_policy)
            )
            return True
        except iam_client.exceptions.UnmodifiableEntityException:
            return False
    else:
        return True

def process_roles_from_csv(file_path, new_trust_policy_statement):
    with open(file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        rows = list(csv_reader)

    table = Table(title="Trust Policy Update Results")
    table.add_column("Account ID")
    table.add_column("Role Name")
    table.add_column("Trust Policy Updated", style="cyan")
    
    results = []
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=len(rows))
        
        for row in rows:
            account_id = row['AccountID']
            role_name = row['RoleName']
            
            credentials = assume_role(account_id, role_name)
            if not credentials:
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'Failed to Assume Role'}
                results.append(result)
                table.add_row(account_id, role_name, result['TrustPolicyUpdated'])
                progress.update(task, advance=1)
                continue
            
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            if update_trust_policy(iam_client, role_name, new_trust_policy_statement):
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'True'}
            else:
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'False'}
            results.append(result)
            table.add_row(account_id, role_name, result['TrustPolicyUpdated'])
            progress.update(task, advance=1)
    
    print(table)
    
    with open('trust_policy_update_results.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['AccountID', 'RoleName', 'TrustPolicyUpdated'])
        writer.writeheader()
        writer.writerows(results)
    
    console = Console()
    console.print("[bold bright_red]Output saved as trust_policy_update_results.csv[/bold bright_red]")

new_trust_policy_statement = {
    "Effect": "Deny",
    "Principal": {
        "AWS": "*"
    },
    "Action": [
        "sts:AssumeRole",
        "sts:AssumeRoleWithWebIdentity"
    ],
    "Condition": {
        "StringNotEqualsIfExists": {
            "aws:PrincipalOrgID": "o-vc3105qz5q",
            "aws:PrincipalAccount": "012345678901"
        },
        "BoolIfExists": {
            "aws:PrincipalIsAWSService": False
        }
    }
}

start_time = time()

process_roles_from_csv('input_roles.csv', new_trust_policy_statement)

end_time = time()
elapsed_time = end_time - start_time

console = Console()
console.print(f"[bold bright_red]Script completed in {elapsed_time:.2f} seconds[/bold bright_red]")
```

### Demo Output
![](https://private-user-images.githubusercontent.com/30806882/341465202-4cfb05fc-ebd9-40ab-82bc-f9070e181e82.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MTkzNDc2MzUsIm5iZiI6MTcxOTM0NzMzNSwicGF0aCI6Ii8zMDgwNjg4Mi8zNDE0NjUyMDItNGNmYjA1ZmMtZWJkOS00MGFiLTgyYmMtZjkwNzBlMTgxZTgyLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA2MjUlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwNjI1VDIwMjg1NVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTMyYjU2M2M0OTY2ODY2MTI2MjQzZTk5MDBkODEyMjUwYzg0MzEyM2Y2MDk2YmIwZjYzY2M2ZmZmYmYyYTgyMmMmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.hZBUK7Bmz8ECPyI-Isij6r4DbrEexrChuxE89-pzvyI)

### Output results in CSV
![](https://private-user-images.githubusercontent.com/30806882/341466549-a3e5f03d-37e6-4ca8-af1b-3a96a9cca323.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MTkzNDc2MzUsIm5iZiI6MTcxOTM0NzMzNSwicGF0aCI6Ii8zMDgwNjg4Mi8zNDE0NjY1NDktYTNlNWYwM2QtMzdlNi00Y2E4LWFmMWItM2E5NmE5Y2NhMzIzLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA2MjUlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwNjI1VDIwMjg1NVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTZlNDExM2MxZWU0ZGRhOTgzN2NkN2ZmOTA2ZmY0ZjNlYzAyOTViNzIwOWE0MTJjYTMxNTJjMjAwOTEzOWRiY2QmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.32WbfIHc-j1eGBCJWi2bLoOSXhZzMZm2vdKef8n6cwo)


