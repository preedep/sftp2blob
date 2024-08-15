#!/bin/bash

# Help function
print_help() {
    echo "Usage: $0 --protocol {sftp|ftps|ftp} --host SFTP_HOST --port SFTP_PORT --remote REMOTE_FILE_PATH --local LOCAL_FILE_PATH --storage-account AZURE_STORAGE_ACCOUNT --container AZURE_CONTAINER_NAME --blob AZURE_BLOB_NAME --vault KEY_VAULT_NAME --username-secret SFTP_USERNAME_SECRET_NAME --password-secret SFTP_PASSWORD_SECRET_NAME --identity MANAGED_IDENTITY_CLIENT_ID"
    echo ""
    echo "Parameters:"
    echo "  --protocol               Specify the transfer protocol to use (SFTP, FTPS, or FTP)."
    echo "  --host                   (Optional) SFTP/FTPS/FTP host. Can also be set as environment variable."
    echo "  --port                   (Optional) SFTP/FTPS/FTP port. Can also be set as environment variable."
    echo "  --remote                 (Optional) Remote file path on SFTP/FTPS/FTP server. Can also be set as environment variable."
    echo "  --local                  (Optional) Local file path to store the downloaded file. Can also be set as environment variable."
    echo "  --storage-account        (Optional) Azure Storage account name. Can also be set as environment variable."
    echo "  --container              (Optional) Azure Blob container name. Can also be set as environment variable."
    echo "  --blob                   (Optional) Azure Blob name. Can also be set as environment variable."
    echo "  --vault                  (Optional) Azure Key Vault name. Can also be set as environment variable."
    echo "  --username-secret        (Optional) Secret name for SFTP/FTPS/FTP username in Key Vault. Can also be set as environment variable."
    echo "  --password-secret        (Optional) Secret name for SFTP/FTPS/FTP password in Key Vault. Can also be set as environment variable."
    echo "  --identity               (Optional) Client ID of the Managed Identity. Can also be set as environment variable."
    echo ""
    echo "Examples:"
    echo "  $0 --protocol sftp"
    echo "  $0 --protocol ftps --host new-host.example.com --port 2222 --remote /new/remote/path --local /new/local/path"
    echo "  $0 --help"
}

# Configuration
SFTP_HOST="${SFTP_HOST:-${2:-ftp.example.com}}"
SFTP_PORT="${SFTP_PORT:-${3:-21}}"
REMOTE_FILE_PATH="${REMOTE_FILE_PATH:-${4:-/remote/path/to/your/file.txt}}"
LOCAL_FILE_PATH="${LOCAL_FILE_PATH:-${5:-/local/path/to/downloaded/file.txt}}"

# Azure Configuration
AZURE_STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-${6:-your_storage_account_name}}"
AZURE_CONTAINER_NAME="${AZURE_CONTAINER_NAME:-${7:-your_container_name}}"
AZURE_BLOB_NAME="${AZURE_BLOB_NAME:-${8:-your_blob_name}}"

# Azure Configuration - Azure Key Vault
KEY_VAULT_NAME="${KEY_VAULT_NAME:-${9:-your-key-vault-name}}"
SFTP_USERNAME_SECRET_NAME="${SFTP_USERNAME_SECRET_NAME:-${10:-ftp-username-secret}}"
SFTP_PASSWORD_SECRET_NAME="${SFTP_PASSWORD_SECRET_NAME:-${11:-ftp-password-secret}}"

# Azure Configuration - Specific Managed Identity
MANAGED_IDENTITY_CLIENT_ID="${MANAGED_IDENTITY_CLIENT_ID:-${12:-your-managed-identity-client-id}}"

# Parse named parameters and override environment variables or defaults
while [[ $# -gt 0 ]]; do
    case $1 in
        --protocol)
            PROTOCOL="$2"
            shift 2
            ;;
        --host)
            SFTP_HOST="$2"
            shift 2
            ;;
        --port)
            SFTP_PORT="$2"
            shift 2
            ;;
        --remote)
            REMOTE_FILE_PATH="$2"
            shift 2
            ;;
        --local)
            LOCAL_FILE_PATH="$2"
            shift 2
            ;;
        --storage-account)
            AZURE_STORAGE_ACCOUNT="$2"
            shift 2
            ;;
        --container)
            AZURE_CONTAINER_NAME="$2"
            shift 2
            ;;
        --blob)
            AZURE_BLOB_NAME="$2"
            shift 2
            ;;
        --vault)
            KEY_VAULT_NAME="$2"
            shift 2
            ;;
        --username-secret)
            SFTP_USERNAME_SECRET_NAME="$2"
            shift 2
            ;;
        --password-secret)
            SFTP_PASSWORD_SECRET_NAME="$2"
            shift 2
            ;;
        --identity)
            MANAGED_IDENTITY_CLIENT_ID="$2"
            shift 2
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown parameter passed: $1"
            print_help
            exit 1
            ;;
    esac
done

# Debugging: Print all values
print_debug_info() {
    echo "Debug Information:"
    echo "  PROTOCOL: $PROTOCOL"
    echo "  SFTP_HOST: $SFTP_HOST"
    echo "  SFTP_PORT: $SFTP_PORT"
    echo "  REMOTE_FILE_PATH: $REMOTE_FILE_PATH"
    echo "  LOCAL_FILE_PATH: $LOCAL_FILE_PATH"
    echo "  AZURE_STORAGE_ACCOUNT: $AZURE_STORAGE_ACCOUNT"
    echo "  AZURE_CONTAINER_NAME: $AZURE_CONTAINER_NAME"
    echo "  AZURE_BLOB_NAME: $AZURE_BLOB_NAME"
    echo "  KEY_VAULT_NAME: $KEY_VAULT_NAME"
    echo "  SFTP_USERNAME_SECRET_NAME: $SFTP_USERNAME_SECRET_NAME"
    echo "  SFTP_PASSWORD_SECRET_NAME: $SFTP_PASSWORD_SECRET_NAME"
    echo "  MANAGED_IDENTITY_CLIENT_ID: $MANAGED_IDENTITY_CLIENT_ID"
    echo "  SFTP_USER: $SFTP_USER"
    echo "  SFTP_PASSWORD: (hidden for security)"
    echo ""
}
# Function to log in with a specific user-assigned managed identity
login_with_managed_identity() {
    local client_id=$1

    # Log in using the user-assigned managed identity's Client ID
    az login --identity --username "$client_id" --allow-no-subscriptions 2>&1
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo "Error: Failed to log in with the managed identity Client ID '$client_id'."
        exit 1
    fi
}

get_secret_from_key_vault() {
    local secret_name=$1
    local secret_value
    local command_output
    local command_error

    # Log in using the specified managed identity
    login_with_managed_identity "$MANAGED_IDENTITY_CLIENT_ID"

    # Attempt to retrieve the secret, capturing stdout and stderr separately
    command_output=$(az keyvault secret show --name "$secret_name" --vault-name "$KEY_VAULT_NAME" --query value --output tsv 2> >(command_error=$(cat); typeset -p command_error > /dev/null))

    # Check if the command was successful
    if [[ $? -ne 0 ]]; then
        if [[ "$command_error" == *"Forbidden"* ]]; then
            echo "Error: Access to secret '$secret_name' in Key Vault '$KEY_VAULT_NAME' is forbidden."
            echo "Please ensure that the managed identity has the correct permissions."
        else
            echo "Error: Failed to retrieve secret '$secret_name' from Key Vault '$KEY_VAULT_NAME'."
            echo "Azure CLI error: $command_error"
        fi
        exit 1
    fi

    # Ensure the output is not empty and does not contain unexpected data
    if [[ -z "$command_output" || "$command_output" == *"{"* ]]; then
        echo "Error: Retrieved value for '$secret_name' appears to be invalid or empty."
        exit 1
    fi

    # Return the retrieved secret value
    echo "$command_output"
}

get_and_validate_user_sftp() {
    # Get FTP/SFTP/FTPS credentials from Azure Key Vault
    SFTP_USER=$(get_secret_from_key_vault "$SFTP_USERNAME_SECRET_NAME")
    SFTP_PASSWORD=$(get_secret_from_key_vault "$SFTP_PASSWORD_SECRET_NAME")

    echo "$SFTP_USER"
    echo "$SFTP_PASSWORD"


    # Debugging: Print all values
    print_debug_info

    # Check if credentials were retrieved
    if [ -z "$SFTP_USER" ] || [ -z "$SFTP_PASSWORD" ]; then
        echo "Failed to retrieve credentials from Azure Key Vault."
        exit 1
    fi

    # Ensure SFTP_USER and SFTP_PASSWORD are not in JSON format
    if [[ "$SFTP_USER" == *"{"* ]] || [[ "$SFTP_PASSWORD" == *"{"* ]]; then
        echo "Error: Credentials retrieved from Azure Key Vault are not valid (appears to be in JSON format)."
        exit 1
    fi
}

# Function to download a file using SFTP
download_from_sftp() {
    echo "Downloading file from SFTP..."
    get_secret_from_key_vault
    sftp -P "$SFTP_PORT" "$SFTP_USER"@"$SFTP_HOST" <<EOF
get $REMOTE_FILE_PATH $LOCAL_FILE_PATH
bye
EOF
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo "Failed to download file from SFTP."
        exit 1
    fi
}

# Function to download a file using FTPS
download_from_ftps() {
    echo "Downloading file from FTPS..."
    get_and_validate_user_sftp
    lftp -u "$SFTP_USER","$SFTP_PASSWORD" -e "get $REMOTE_FILE_PATH -o $LOCAL_FILE_PATH; bye" ftps://"$SFTP_HOST"
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo "Failed to download file from FTPS."
        exit 1
    fi
}

# Function to download a file using FTP
download_from_ftp() {
    echo "Downloading file from FTP..."
    get_and_validate_user_sftp
    # shellcheck disable=SC2086
    lftp -u "$SFTP_USER","$SFTP_PASSWORD" -e "get $REMOTE_FILE_PATH -o $LOCAL_FILE_PATH; bye" ftp://"$SFTP_HOST"
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo "Failed to download file from FTP."
        exit 1
    fi
}

# Function to upload a file to Azure Blob Storage using azcopy
upload_to_azure_blob() {
    echo "Uploading file to Azure Blob Storage..."
    azcopy copy "$LOCAL_FILE_PATH" "https://$AZURE_STORAGE_ACCOUNT.blob.core.windows.net/$AZURE_CONTAINER_NAME/$AZURE_BLOB_NAME" --from-to=LocalBlob --auth-mode=MSI --identity="$MANAGED_IDENTITY_CLIENT_ID"
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo "Failed to upload file to Azure Blob Storage."
        exit 1
    fi
}

# Main script logic
if [ "$PROTOCOL" == "sftp" ]; then
    download_from_sftp
elif [ "$PROTOCOL" == "ftps" ]; then
    download_from_ftps
elif [ "$PROTOCOL" == "ftp" ]; then
    download_from_ftp
else
    echo "Invalid protocol. Please specify --protocol {sftp|ftps|ftp}"
    print_help
    exit 1
fi

upload_to_azure_blob

# Cleanup (optional)
rm -f "$LOCAL_FILE_PATH"

echo "File transfer completed successfully."