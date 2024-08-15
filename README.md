# SFTP2Blob - A simple shell script to copy files from SFTP to Azure Blob Storage

This script is a simple shell script that copies files from SFTP or FTPs to Azure Blob Storage. 
It uses the `sftp` or `lftp` command to connect to the SFTP server and `azcopy` to copy files to Azure Blob Storage.

## Prerequisites
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [AzCopy](https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)
- [lftp](https://lftp.yar.ru/)
- sftp
- Azure Blob Storage account
- Azure Key Vault (store the SFTP/FTPs user/password)
- 