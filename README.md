# SFTP2Blob - A simple shell script to copy files from SFTP to Azure Blob Storage

This script is a simple shell script that copies files from SFTP or FTPs to Azure Blob Storage. 
It uses the `sftp` or `lftp` command to connect to the SFTP server and `azcopy` to copy files to Azure Blob Storage.

## Usage
```bash
./sftp2blob.sh --help
```
Example usage: Environment variables
```bash
export SFTP_HOST="new-host.example.com"
export SFTP_PORT="2222"
./sftp2blob.sh sftp
```

Example usage: Command line arguments
```bash
./sftp2blob.sh sftp new-host.example.com 2222 /new/remote/path /new/local/path
````

## Configuration Environment Variables
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

## Prerequisites
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [AzCopy](https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)
- [lftp](https://lftp.yar.ru/)
- [sftp](https://linuxize.com/post/how-to-use-linux-sftp-command-to-transfer-files/)
- Azure Blob Storage account
- Azure Key Vault (store the SFTP/FTPs user/password)
