#!/bin/bash
# Define the latest Azure REST API versions
AZURE_KEY_VAULT_API_VERSION="7.5"
AZURE_STORAGE_API_VERSION="2023-08-03"

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
# Function to retrieve a secret from Azure Key Vault
get_az_key_vault_secret() {
    local secret_name=$1
    local access_token=$2
    local vault_name=$3

    # Make the API request and capture the response and status code separately
    response=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $access_token" \
                "https://${vault_name}.vault.azure.net/secrets/${secret_name}?api-version=${AZURE_KEY_VAULT_API_VERSION}")

    # Extract the body and the status code
    http_body=$(echo "$response" | sed '$ d')  # Everything except the last line
    http_status=$(echo "$response" | tail -n1) # The last line is the status code

    # Check if the request was successful
    if [ "$http_status" -ne 200 ]; then
        echo "Error: Failed to retrieve secret '${secret_name}' from Key Vault '${vault_name}'. HTTP Status: $http_status"
        echo "Response: $http_body"
        exit 1
    fi

    # Return the secret value
    echo "$http_body" | jq -r '.value'
}

# Function to upload a chunk to Azure Blob Storage
upload_chunk_to_azure_blob() {
    local access_token=$1
    local storage_account=$2
    local container_name=$3
    local blob_name=$4
    local block_id=$5

    response=$(curl -v -X PUT -s -w "%{http_code}" \
                -H "Authorization: Bearer $access_token" \
                -H "x-ms-blob-type: BlockBlob" \
                -H "x-ms-version: ${AZURE_STORAGE_API_VERSION}" \
                --data-binary @- \
                "https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}?comp=block&blockid=${block_id}")

    http_status=$(echo "$response" | tail -n1)

    if [ "$http_status" -ne 201 ]; then
        echo "Error: Failed to upload chunk '$block_id' to Azure Blob Storage. HTTP Status: $http_status"
        exit 1
    fi

    echo "Successfully uploaded chunk with block ID $block_id"
}

# Function to commit the uploaded blocks to Azure Blob Storage
commit_blocks_to_azure_blob() {
    local access_token=$1
    local storage_account=$2
    local container_name=$3
    local blob_name=$4
    local block_list_xml=$5

    response=$(curl -v -X PUT -s -w "%{http_code}" \
                -H "Authorization: Bearer $access_token" \
                -H "x-ms-version: ${AZURE_STORAGE_API_VERSION}" \
                -H "Content-Type: application/xml" \
                --data "$block_list_xml" \
                "https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}?comp=blocklist")

    http_status=$(echo "$response" | tail -n1)

    if [ "$http_status" -ne 201 ]; then
        echo "Error: Failed to commit blocks to Azure Blob Storage. HTTP Status: $http_status"
        exit 1
    fi

    echo "Successfully committed blocks to create the final blob."
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
echo "Obtaining access token for Azure Key Vault..."
access_token=$(get_access_token "https://vault.azure.net" "$MANAGED_IDENTITY_CLIENT_ID")

# Get secrets from Azure Key Vault
echo "Retrieving secrets from Azure Key Vault..."
SFTP_USER=$(get_az_key_vault_secret "$SFTP_USERNAME_SECRET_NAME" "$access_token" "$KEY_VAULT_NAME")
SFTP_PASSWORD=$(get_az_key_vault_secret "$SFTP_PASSWORD_SECRET_NAME" "$access_token" "$KEY_VAULT_NAME")

# Check if secrets were retrieved
if [ -z "$SFTP_USER" ] || [ -z "$SFTP_PASSWORD" ]; then
    echo "Failed to retrieve credentials from Azure Key Vault."
    exit 1
fi

echo "Successfully retrieved credentials from Azure Key Vault."

# Function to stream file from SFTP/FTP/FTPS to Azure Blob Storage
stream_file_to_blob() {
    local access_token=$1
    local storage_account=$2
    local container_name=$3
    local blob_name=$4
    local chunk_size=${5:-67108864}  # Default to 64 MB

    BLOCK_ID_LIST=()
    BLOCK_INDEX=0

    echo "Starting file transfer from $PROTOCOL server to Azure Blob Storage..."

    if [ "$PROTOCOL" == "sftp" ]; then
        command="sftp"
        options="-P $SFTP_PORT $SFTP_USER@$SFTP_HOST"
        fetch_command="get -o - $REMOTE_FILE_PATH"
    elif [ "$PROTOCOL" == "ftps" ] || [ "$PROTOCOL" == "ftp" ]; then
        command="lftp"
        options="-u $SFTP_USER,$SFTP_PASSWORD -p $SFTP_PORT $SFTP_HOST"
        fetch_command="set ftp:passive-mode on; cat $REMOTE_FILE_PATH; bye"
    else
        echo "Invalid protocol. Please specify --protocol {sftp|ftps|ftp}"
        print_help
        exit 1
    fi

    echo "Connecting to $SFTP_HOST via $PROTOCOL..."

    full_command="$command $options -e \"$fetch_command\""

    # Debugging: Log the command being run
    echo "Running command: $full_command"

    # Stream the data directly in chunks using dd
    eval "$full_command" | tee data_stream.log | while :; do
        # Generate a unique block ID for each chunk
        BLOCK_ID=$(printf '%06d' $BLOCK_INDEX | base64)
        BLOCK_INDEX=$((BLOCK_INDEX + 1))

        # Create a temporary file for the chunk
        chunk_file=$(mktemp)

        # Read a chunk of data directly into the file
        dd bs="$chunk_size" count=1 iflag=fullblock of="$chunk_file" 2>/dev/null

        # Get the actual size of the chunk read
        chunk_size_uploaded=$(stat -c%s "$chunk_file")

        # If the chunk size is zero, we have reached the end of the file
        if [ "$chunk_size_uploaded" -eq 0 ]; then
            echo "No more data to process. Ending the transfer."
            rm -f "$chunk_file"
            break
        fi

        # Debugging: Log the chunk details
        echo "Uploading chunk with Block ID $BLOCK_ID (Size: $chunk_size_uploaded bytes)..."
        cat "$chunk_file" >> last_chunk.log

        # Add the block ID to the list
        BLOCK_ID_LIST+=("<Latest>$BLOCK_ID</Latest>")

        # Upload the chunk to Azure Blob Storage
        upload_chunk_to_azure_blob "$access_token" "$storage_account" "$container_name" "$blob_name" "$BLOCK_ID" < "$chunk_file"

        # Clean up the temporary chunk file
        rm -f "$chunk_file"
    done

    # Create the block list XML
    BLOCK_LIST_XML="<BlockList>"
    for block in "${BLOCK_ID_LIST[@]}"; do
        BLOCK_LIST_XML+="$block"
    done
    BLOCK_LIST_XML+="</BlockList>"

    # Commit the blocks to create the final blob
    echo "Committing blocks to finalize the blob..."
    commit_blocks_to_azure_blob "$access_token" "$storage_account" "$container_name" "$blob_name" "$BLOCK_LIST_XML"

    echo "File transfer completed successfully."
}

# Obtain access token for Azure Storage
echo "Obtaining access token for Azure Storage..."
access_token=$(get_access_token "https://storage.azure.com/" "$MANAGED_IDENTITY_CLIENT_ID")

# Call the function to upload the file in chunks
stream_file_to_blob "$access_token" "$AZURE_STORAGE_ACCOUNT" "$AZURE_CONTAINER_NAME" "$AZURE_BLOB_NAME"

echo "All operations completed successfully."
exit 0  # Explicitly exit the script to prevent looping
