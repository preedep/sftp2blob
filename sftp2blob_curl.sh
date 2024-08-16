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

# Azure REST API endpoints
get_az_key_vault_secret() {
    local secret_name=$1
    local access_token=$2
    local vault_name=$3

    curl -s -H "Authorization: Bearer $access_token" "https://${vault_name}.vault.azure.net/secrets/${secret_name}?api-version=7.3" | jq -r '.value'
}

upload_chunk_to_azure_blob() {
    local access_token=$1
    local storage_account=$2
    local container_name=$3
    local blob_name=$4
    local chunk_file_path=$5
    local block_id=$6

    curl -X PUT \
         -H "Authorization: Bearer $access_token" \
         -H "x-ms-blob-type: BlockBlob" \
         -H "x-ms-version: 2020-04-08" \
         -H "x-ms-blob-content-md5: $(openssl dgst -md5 -binary "$chunk_file_path" | base64)" \
         --data-binary @"$chunk_file_path" \
         "https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}?comp=block&blockid=${block_id}"
}

commit_blocks_to_azure_blob() {
    local access_token=$1
    local storage_account=$2
    local container_name=$3
    local blob_name=$4
    local block_list_xml=$5

    curl -X PUT \
         -H "Authorization: Bearer $access_token" \
         -H "x-ms-version: 2020-04-08" \
         -H "Content-Type: application/xml" \
         --data "$block_list_xml" \
         "https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}?comp=blocklist"
}

# Function to obtain an access token for Azure services using managed identity
get_access_token() {
    local resource=$1
    local client_id=$2

    curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=${resource}&client_id=${client_id}" -H Metadata:true | jq -r '.access_token'
}

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

# Obtain access token for Key Vault
access_token=$(get_access_token "https://vault.azure.net" "$MANAGED_IDENTITY_CLIENT_ID")

# Get secrets from Azure Key Vault
SFTP_USER=$(get_az_key_vault_secret "$SFTP_USERNAME_SECRET_NAME" "$access_token" "$KEY_VAULT_NAME")
SFTP_PASSWORD=$(get_az_key_vault_secret "$SFTP_PASSWORD_SECRET_NAME" "$access_token" "$KEY_VAULT_NAME")


# Check if secrets were retrieved
if [ -z "$SFTP_USER" ] || [ -z "$SFTP_PASSWORD" ]; then
    echo "Failed to retrieve credentials from Azure Key Vault."
    exit 1
fi

# Function to download a file using SFTP, FTPS, or FTP
download_file() {
    case $PROTOCOL in
        sftp)
            echo "Downloading file from SFTP..."
            sftp -P "$SFTP_PORT" "$SFTP_USER"@"$SFTP_HOST" <<EOF
get $REMOTE_FILE_PATH $LOCAL_FILE_PATH
bye
EOF
            ;;
        ftps)
            echo "Downloading file from FTPS..."
            lftp -u "$SFTP_USER","$SFTP_PASSWORD" -e "get $REMOTE_FILE_PATH -o $LOCAL_FILE_PATH; bye" ftps://"$SFTP_HOST"
            ;;
        ftp)
            echo "Downloading file from FTP..."
            lftp -u "$SFTP_USER","$SFTP_PASSWORD" -e "get $REMOTE_FILE_PATH -o $LOCAL_FILE_PATH; bye" ftp://"$SFTP_HOST"
            ;;
        *)
            echo "Invalid protocol. Please specify --protocol {sftp|ftps|ftp}"
            print_help
            exit 1
            ;;
    esac
}

# Download file using specified protocol
download_file

# Function to upload a file in chunks to Azure Blob Storage
upload_file_in_chunks_to_azure_blob() {
    local access_token=$1
    local storage_account=$2
    local container_name=$3
    local blob_name=$4
    local local_file_path=$5
    local chunk_size=${6:-4194304}  # Default to 4 MB

    # Initialize variables
    BLOCK_ID_LIST=()
    BLOCK_INDEX=0

    # Split the file into chunks and upload each chunk
    while IFS= read -r -d '' chunk; do
        BLOCK_ID=$(printf '%06d' $((BLOCK_INDEX++)))
        BLOCK_ID_B64=$(echo -n "$BLOCK_ID" | base64)
        BLOCK_ID_LIST+=("<Latest>$BLOCK_ID_B64</Latest>")
        upload_chunk_to_azure_blob "$access_token" "$storage_account" "$container_name" "$blob_name" "$chunk" "$BLOCK_ID_B64"
    done < <(split -b "$chunk_size" -a 6 -d --additional-suffix=.chunk "$local_file_path" "${local_file_path}.chunk.")

    # Create the block list XML
    BLOCK_LIST_XML="<BlockList>"
    for block in "${BLOCK_ID_LIST[@]}"; do
        BLOCK_LIST_XML+="$block"
    done
    BLOCK_LIST_XML+="</BlockList>"

    # Commit the blocks to create the final blob
    commit_blocks_to_azure_blob "$access_token" "$storage_account" "$container_name" "$blob_name" "$BLOCK_LIST_XML"

    # Cleanup (optional)
    rm -f "${local_file_path}.chunk.*"
}

# Obtain access token for Azure Storage
access_token=$(get_access_token "https://storage.azure.com/" "$MANAGED_IDENTITY_CLIENT_ID")

# Call the function to upload the file in chunks
upload_file_in_chunks_to_azure_blob "$access_token" "$AZURE_STORAGE_ACCOUNT" "$AZURE_CONTAINER_NAME" "$AZURE_BLOB_NAME" "$LOCAL_FILE_PATH"

# Cleanup (optional)
rm -f "${LOCAL_FILE_PATH}.chunk.*"
rm -f "$LOCAL_FILE_PATH"

echo "File transfer completed successfully."