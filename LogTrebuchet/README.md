# About

This PowerShell script downloads sample data and injects them to our sample Log Analytic Workspace, MSSen2GoCLug22vxas67urs, on ATEVET17

# Versions

- Version 1 is the original implementation which sends one line of the downloaded JSON file at a time
- Version 2 is an updated version that sends data in chunks
- Version 3 is a bit more optimized and checks for the size of what will be sent at once


# Resource Deployment

Azue CLI:

1.  az login
2.  az group create --name "<RGName>"
3.  az deployment group create --resource-group "<RGName>" --template-file azuredeploy.json
4.  Create an app (you can do this in the Azure portal) and add a secret to it (and save the secret)

# Run

To run this script simply type on your terminal:

.\wrapper_script4.ps1

