# SFTP2Blob - A simple shell script (Linux) to copy files from SFTP/FTPs/FTP to Azure Blob Storage

This script is a simple shell script that copies files from SFTP or FTPs or FTP Server to Azure Blob Storage. 
It uses the `sftp` or `lftp` command to connect to the SFTP/FTPs/FTP server and `azcopy` to copy files to Azure Blob Storage.
The script uses the **Azure Key Vault to store the SFTP/FTPs username and password**. and **specific managed identity** to access Azure Key Vault and Azure Blob Storage.

I've 2 versions of the script:
1. `sftp2blob.sh` - The basic version of the script that uses the `sftp` or `lftp` command to connect to the SFTP/FTPs/FTP server and `azcopy` to copy files to Azure Blob Storage.
2. `sftp2blob_curl.sh` - The enhanced version of the script that uses `curl` to connect to the Azure REST API of Azure Key Vault and Azure Blob Storage. (more detail in the enhancements section)


## Diagram
```mermaid
sequenceDiagram
    SFTP2BLOB->>AZURE_KEY_VAULT: Get User and Password with AZ CLI with specific managed identity
    SFTP2BLOB-->>FTP_SERVER: Get File and Authen with User and Password
    SFTP2BLOB-->>SFTP2BLOB: Save Data to Local
    SFTP2BLOB-->>CALL_AZ_COPY: Run AZ Copy with specific managed identity
```

## Usage
The script can combine with command line arguments and environment variables.
```bash
./sftp2blob.sh --help
```
```chatinput
Usage: ./sftp2blob.sh --protocol {sftp|ftps|ftp} --host SFTP_HOST --port SFTP_PORT --remote REMOTE_FILE_PATH --local LOCAL_FILE_PATH --storage-account AZURE_STORAGE_ACCOUNT --container AZURE_CONTAINER_NAME --blob AZURE_BLOB_NAME --vault KEY_VAULT_NAME --username-secret SFTP_USERNAME_SECRET_NAME --password-secret SFTP_PASSWORD_SECRET_NAME --identity MANAGED_IDENTITY_CLIENT_ID

Parameters:
  --protocol               Specify the transfer protocol to use (SFTP, FTPS, or FTP).
  --host                   (Optional) SFTP/FTPS/FTP host. Can also be set as environment variable.
  --port                   (Optional) SFTP/FTPS/FTP port. Can also be set as environment variable.
  --remote                 (Optional) Remote file path on SFTP/FTPS/FTP server. Can also be set as environment variable.
  --local                  (Optional) Local file path to store the downloaded file. Can also be set as environment variable.
  --storage-account        (Optional) Azure Storage account name. Can also be set as environment variable.
  --container              (Optional) Azure Blob container name. Can also be set as environment variable.
  --blob                   (Optional) Azure Blob name. Can also be set as environment variable.
  --vault                  (Optional) Azure Key Vault name. Can also be set as environment variable.
  --username-secret        (Optional) Secret name for SFTP/FTPS/FTP username in Key Vault. Can also be set as environment variable.
  --password-secret        (Optional) Secret name for SFTP/FTPS/FTP password in Key Vault. Can also be set as environment variable.
  --identity               (Optional) Client ID of the Managed Identity. Can also be set as environment variable.

Examples:
  ./sftp2blob.sh --protocol sftp
  ./sftp2blob.sh --protocol ftps --host new-host.example.com --port 2222 --remote /new/remote/path --local /new/local/path
  ./sftp2blob.sh --help
```
## Environment Variables
The script uses the following environment variables to configure the SFTP/FTPs and Azure Blob Storage connection:
```bash
export SFTP_HOST="sftp.example.com"
export SFTP_PORT="22"
export REMOTE_FILE_PATH="/remote/path/to/your/file.txt"
export LOCAL_FILE_PATH="/local/path/to/downloaded/file.txt"

#Azure Configuration
export AZURE_STORAGE_ACCOUNT="your_storage_account_name"
export AZURE_CONTAINER_NAME="your_container_name"
export AZURE_BLOB_NAME="your_blob_name"

#Azure Configuration - Azure Key Vault
export KEY_VAULT_NAME="your-key-vault-name"
export SFTP_USERNAME_SECRET_NAME="sftp-username-secret"
export SFTP_PASSWORD_SECRET_NAME="sftp-password-secret"

#Azure Configuration - Specific Managed Identity 
export MANAGED_IDENTITY_CLIENT_ID="your-managed-identity-client-id"
```

Example usage: Environment variables (combine with command line arguments)
```bash
export SFTP_HOST="new-host.example.com"
export SFTP_PORT="2222"
./sftp2blob.sh --protocol sftp
```

Example usage: Command line arguments
```bash
./sftp2blob.sh --protocol ftps --host new-host.example.com --port 2222 --remote /new/remote/path --local /new/local/path
````

## Prerequisites 
### 1) Software dependencies on Linux Server
but if you run with docker you don't need to install the following tools. my dockerfile already installed all the tools.
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [AzCopy](https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)
- [lftp](https://lftp.yar.ru/)
- [sftp](https://linuxize.com/post/how-to-use-linux-sftp-command-to-transfer-files/)
- [jq](https://stedolan.github.io/jq/)

#### Azure CLI (Add extensions)
For this script will add all available extensions to the Azure CLI.
```bash
for extension in $(az extension list-available --query "[].name" -o tsv); do
  az extension add --name $extension
done
```

### 2) Azure Resources
- Azure VM (Linux) (for run the script)
- Azure Blob Storage account
- Azure Key Vault (store the SFTP/FTPs user/password)
- Azure Managed Identity (for access Azure Key Vault and Azure Blob Storage)

#### From Azure Portal
Key Vault - Secrets
![Key Vault - Secrets](imgs/keyvault.png)

Azure Blob Storage - Containers (Output after run script)
![Azure Blob Storage - Containers](imgs/blobstorage.png)

Managed Identity 
![Managed Identity](imgs/msi1.png)
Attach the managed identity to the Azure VM (Linux)
![Attach the managed identity to the Azure VM (Linux)](imgs/msi2.png)


## Example for run shell script
This example uses the `ftp` protocol to connect to the FTP server (localhost) and copy the file `test.csv` to the Azure Blob Storage account `nickdevstorage003` and container `datas` with the blob name `test.csv`. The script uses the Azure Key Vault `nickkvdev001` to store the FTP username and password.
```bash
./sftp2blob.sh --protocol ftp \
    --host localhost \
    --port 22 \
    --remote /upload/test.csv \
    --local test.csv \
    --storage-account nickdevstorage003 \
    --container datas \
    --blob test.csv \
    --vault nickkvdev001 \
    --username-secret FTP-USER \
    --password-secret FTP-PASSWORD \
    --identity <<client-id>> of managed identity
```
Example output after running the script:
```chatinput
Downloading file from FTP...
ftpuser001
password
Debug Information:
  PROTOCOL: ftp
  SFTP_HOST: localhost
  SFTP_PORT: 22
  REMOTE_FILE_PATH: /upload/test.csv
  LOCAL_FILE_PATH: test.csv
  AZURE_STORAGE_ACCOUNT: nickdevstorage003
  AZURE_CONTAINER_NAME: datas
  AZURE_BLOB_NAME: test.csv
  KEY_VAULT_NAME: nickkvdev001
  SFTP_USERNAME_SECRET_NAME: FTP-USER
  SFTP_PASSWORD_SECRET_NAME: FTP-PASSWORD
  MANAGED_IDENTITY_CLIENT_ID: <<client-id>> of managed identity
  SFTP_USER: ftpuser001
  SFTP_PASSWORD: (hidden for security)

15 bytes transferred
Uploading file to Azure Blob Storage...
WARN: The flags --service-principal and --identity will be deprecated in a future release. Please use --login-type=SPN or --login-type=MSI instead.
INFO: Login with identity succeeded.
INFO: Scanning...
INFO: Autologin not specified.
INFO: Authenticating to destination using Azure AD
INFO: Any empty folders will not be processed, because source and/or destination doesn't have full folder support

Job 51905158-2547-7444-4945-786560fc9e54 has started
Log file is located at: /home/azureuser/.azcopy/51905158-2547-7444-4945-786560fc9e54.log

100.0 %, 1 Done, 0 Failed, 0 Pending, 0 Skipped, 1 Total, 2-sec Throughput (Mb/s): 0.0001


Job 51905158-2547-7444-4945-786560fc9e54 summary
Elapsed Time (Minutes): 0.0334
Number of File Transfers: 1
Number of Folder Property Transfers: 0
Number of Symlink Transfers: 0
Total Number of Transfers: 1
Number of File Transfers Completed: 1
Number of Folder Transfers Completed: 0
Number of File Transfers Failed: 0
Number of Folder Transfers Failed: 0
Number of File Transfers Skipped: 0
Number of Folder Transfers Skipped: 0
Total Number of Bytes Transferred: 15
Final Job Status: Completed

INFO: Logout succeeded.
File transfer completed successfully.

```
## For Docker
in-case connect to localhost use `host.docker.internal` instead of `localhost` 
Build the Docker image
```bash
docker build -t sftp2blob-img:latest .
```

Run the Docker container (with cli arguments)
```bash
docker run -it --rm --name sftp2blob sftp2blob-img:latest --protocol ftp \
    --host host.docker.internal \
    --port 21 \
    --remote /upload/test.csv \
    --local test.csv \
    --storage-account nickdevstorage003 \
    --container datas \
    --blob test.csv \
    --vault nickkvdev001 \
    --username-secret FTP-USER \
    --password-secret FTP-PASSWORD \
    --identity <<client-id>> of managed identity
```
Run the Docker container (with environment variables) #1
```bash
docker run -it --rm --name sftp2blob sftp2blob-img:latest --protocol ftp \
    -e SFTP_HOST=host.docker.internal \
    -e SFTP_PORT=21 \
    -e REMOTE_FILE_PATH=/upload/test.csv \
    -e LOCAL_FILE_PATH=test.csv \
    -e AZURE_STORAGE_ACCOUNT=nickdevstorage003 \
    -e AZURE_CONTAINER_NAME=datas \
    -e AZURE_BLOB_NAME=test.csv \
    -e KEY_VAULT_NAME=nickkvdev001 \
    -e SFTP_USERNAME_SECRET_NAME=FTP-USER \
    -e SFTP_PASSWORD_SECRET_NAME=FTP-PASSWORD \
    -e MANAGED_IDENTITY_CLIENT_ID=<<client-id>> \
    
```
Run the Docker container (with environment variables) #2
```bash
# Set the environment variables
export SFTP_HOST=localhost
export SFTP_PORT=21
export REMOTE_FILE_PATH=/upload/test.csv
export LOCAL_FILE_PATH=test.csv
export AZURE_STORAGE_ACCOUNT=nickdevstorage003
export AZURE_CONTAINER_NAME=datas
export AZURE_BLOB_NAME=test.csv
export KEY_VAULT_NAME=nickkvdev001
export SFTP_USERNAME_SECRET_NAME=FTP-USER
export SFTP_PASSWORD_SECRET_NAME=FTP-PASSWORD
export MANAGED_IDENTITY_CLIENT_ID=<<client-id>>

# Run the Docker container
docker run -it --rm --name sftp2blob sftp2blob-img:latest
```

## SFTP2BLOB enhancements
After implementing the basic functionality of the script, you can enhance the script with the following features:
- Reduce software dependencies like a Azure CLI , AzCopy , Python , etc.
- Uses curl for Azure REST API of Azure key vault and Blob Storage
- Streaming the file from SFTP/FTPs/FTP to Azure Blob Storage (without saving the file to local)
- Enhance memory usage and performance

new script: `sftp2blob_curl.sh`

### Example (for CLI arguments or Environment Variables is same as above)
#### Example for run shell script
```bash
./sftp2blob_curl.sh --protocol ftp \
    --host localhost \
    --port 21 \
    --remote /upload/test.csv \
    --local test.csv \
    --storage-account nickdevstorage003 \
    --container datas \
    --blob test.csv \
    --vault nickkvdev001 \
    --username-secret FTP-USER \
    --password-secret FTP-PASSWORD \
    --identity <<client-id>> of managed identity
```
#### Example for run Docker (Development)
```bash
docker stop sftp2blob-curl
docker rm sftp2blob-curl
docker run -it --rm --name sftp2blob-curl \
    -v "$(pwd)":/var/tmp/ \
    -e SFTP_HOST=host.docker.internal \
    -e SFTP_PORT=21 \
    -e REMOTE_FILE_PATH=/upload/big1g.dat \
    -e LOCAL_FILE_PATH=big1g.dat \
    -e AZURE_STORAGE_ACCOUNT=nickdevstorage003 \
    -e AZURE_CONTAINER_NAME=datas \
    -e AZURE_BLOB_NAME=big1g.dat \
    -e KEY_VAULT_NAME=nickkvdev001 \
    -e SFTP_USERNAME_SECRET_NAME=FTP-USER \
    -e SFTP_PASSWORD_SECRET_NAME=FTP-PASSWORD \
    -e MANAGED_IDENTITY_CLIENT_ID=afc87ccf-6294-4ac7-9533-179fb67f6c8b \
    sftp2blob-curl-img:latest  --protocol ftp

# View logs after the container exits
docker logs sftp2blob-curl
    
```