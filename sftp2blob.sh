#!/bin/bash

# Help function
print_help() {
    echo "Usage: $0 {sftp|ftps} [SFTP_HOST] [SFTP_PORT] [REMOTE_FILE_PATH] [LOCAL_FILE_PATH] [AZURE_STORAGE_ACCOUNT] [AZURE_CONTAINER_NAME] [AZURE_BLOB_NAME] [KEY_VAULT_NAME] [SFTP_USERNAME_SECRET_NAME] [SFTP_PASSWORD_SECRET_NAME] [MANAGED_IDENTITY_CLIENT_ID]"
    echo ""
    echo "Parameters:"
    echo "  sftp|ftps                Specify the transfer protocol to use (SFTP or FTPS)."
    echo "  SFTP_HOST                (Optional) SFTP/FTPS host. Can also be set as environment variable."
    echo "  SFTP_PORT                (Optional) SFTP/FTPS port. Can also be set as environment variable."
    echo "  REMOTE_FILE_PATH         (Optional) Remote file path on SFTP/FTPS server. Can also be set as environment variable."
    echo "  LOCAL_FILE_PATH          (Optional) Local file path to store the downloaded file. Can also be set as environment variable."
    echo "  AZURE_STORAGE_ACCOUNT    (Optional) Azure Storage account name. Can also be set as environment variable."
    echo "  AZURE_CONTAINER_NAME     (Optional) Azure Blob container name. Can also be set as environment variable."
    echo "  AZURE_BLOB_NAME          (Optional) Azure Blob name. Can also be set as environment variable."
    echo "  KEY_VAULT_NAME           (Optional) Azure Key Vault name. Can also be set as environment variable."
    echo "  SFTP_USERNAME_SECRET_NAME(Optional) Secret name for SFTP/FTPS username in Key Vault. Can also be set as environment variable."
    echo "  SFTP_PASSWORD_SECRET_NAME(Optional) Secret name for SFTP/FTPS password in Key Vault. Can also be set as environment variable."
    echo "  MANAGED_IDENTITY_CLIENT_ID(Optional) Client ID of the Managed Identity. Can also be set as environment variable."
    echo ""
    echo "Examples:"
    echo "  $0 sftp"
    echo "  $0 ftps new-host.example.com 2222 /new/remote/path /new/local/path"
    echo "  $0 --help"
}

# Check if help is requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    print_help
    exit 0
fi
# Configuration
# File transfer - SFTP or FTPs
SFTP_HOST="${SFTP_HOST:-${2:-sftp.example.com}}"
SFTP_PORT="${SFTP_PORT:-${3:-22}}"
REMOTE_FILE_PATH="${REMOTE_FILE_PATH:-${4:-/remote/path/to/your/file.txt}}"
LOCAL_FILE_PATH="${LOCAL_FILE_PATH:-${5:-/local/path/to/downloaded/file.txt}}"

#Azure Configuration
AZURE_STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-${6:-your_storage_account_name}}"
AZURE_CONTAINER_NAME="${AZURE_CONTAINER_NAME:-${7:-your_container_name}}"
AZURE_BLOB_NAME="${AZURE_BLOB_NAME:-${8:-your_blob_name}}"

#Azure Configuration - Azure Key Vault
KEY_VAULT_NAME="${KEY_VAULT_NAME:-${9:-your-key-vault-name}}"
SFTP_USERNAME_SECRET_NAME="${SFTP_USERNAME_SECRET_NAME:-${10:-sftp-username-secret}}"
SFTP_PASSWORD_SECRET_NAME="${SFTP_PASSWORD_SECRET_NAME:-${11:-sftp-password-secret}}"

#Azure Configuration - Specific Managed Identity 
MANAGED_IDENTITY_CLIENT_ID="${MANAGED_IDENTITY_CLIENT_ID:-${12:-your-managed-identity-client-id}}"

# Function to get secret from Azure Key Vault using Managed Identity
get_secret_from_key_vault() {
    local secret_name=$1
    az keyvault secret show --name $secret_name --vault-name $KEY_VAULT_NAME --query value --output tsv --identity $MANAGED_IDENTITY_CLIENT_ID
}

# Get SFTP/FTPS credentials from Azure Key Vault
SFTP_USER=$(get_secret_from_key_vault $SFTP_USERNAME_SECRET_NAME)
SFTP_PASSWORD=$(get_secret_from_key_vault $SFTP_PASSWORD_SECRET_NAME)

# Check if credentials were retrieved
if [ -z "$SFTP_USER" ] || [ -z "$SFTP_PASSWORD" ]; then
    echo "Failed to retrieve SFTP credentials from Azure Key Vault."
    exit 1
fi

echo "Successfully retrieved credentials from Azure Key Vault."

# Function to download a file using SFTP
download_from_sftp() {
    echo "Downloading file from SFTP..."
    sftp -P $SFTP_PORT $SFTP_USER@$SFTP_HOST <<EOF
get $REMOTE_FILE_PATH $LOCAL_FILE_PATH
bye
EOF
    if [ $? -ne 0 ]; then
        echo "Failed to download file from SFTP."
        exit 1
    fi
}

# Function to download a file using FTPS
download_from_ftps() {
    echo "Downloading file from FTPS..."
    lftp -u $SFTP_USER,$SFTP_PASSWORD -e "get $REMOTE_FILE_PATH -o $LOCAL_FILE_PATH; bye" ftps://$SFTP_HOST
    if [ $? -ne 0 ]; then
        echo "Failed to download file from FTPS."
        exit 1
    fi
}

# Function to upload a file to Azure Blob Storage using azcopy
upload_to_azure_blob() {
    echo "Uploading file to Azure Blob Storage..."
    azcopy copy "$LOCAL_FILE_PATH" "https://$AZURE_STORAGE_ACCOUNT.blob.core.windows.net/$AZURE_CONTAINER_NAME/$AZURE_BLOB_NAME" --from-to=LocalBlob --auth-mode=MSI --identity="$MANAGED_IDENTITY_CLIENT_ID"
    if [ $? -ne 0 ]; then
        echo "Failed to upload file to Azure Blob Storage."
        exit 1
    fi
}

# Main script logic
if [ "$1" == "sftp" ]; then
    download_from_sftp
elif [ "$1" == "ftps" ]; then
    download_from_ftps
else
    echo "Usage: $0 {sftp|ftps}"
    exit 1
fi

upload_to_azure_blob

# Cleanup (optional)
rm -f $LOCAL_FILE_PATH

echo "File transfer completed successfully."
