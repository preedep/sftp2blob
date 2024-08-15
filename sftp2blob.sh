#!/bin/bash

# Configuration
# File transfer - SFTP or FTPs
SFTP_HOST="sftp.example.com"
SFTP_PORT="22"
REMOTE_FILE_PATH="/remote/path/to/your/file.txt"
LOCAL_FILE_PATH="/local/path/to/downloaded/file.txt"

#Azure Configuration
AZURE_STORAGE_ACCOUNT="your_storage_account_name"
AZURE_CONTAINER_NAME="your_container_name"
AZURE_BLOB_NAME="your_blob_name"

#Azure Configuration - Azure Key Vault
KEY_VAULT_NAME="your-key-vault-name"
SFTP_USERNAME_SECRET_NAME="sftp-username-secret"
SFTP_PASSWORD_SECRET_NAME="sftp-password-secret"

#Azure Configuration - Specific Managed Identity 
MANAGED_IDENTITY_CLIENT_ID="your-managed-identity-client-id"

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
