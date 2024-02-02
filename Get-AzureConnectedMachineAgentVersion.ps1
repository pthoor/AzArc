function Get-AzureConnectedMachineAgentVersion {
    # Define the URL for the Microsoft Update Catalog
    $searchUrl = 'https://www.catalog.update.microsoft.com/Search.aspx?q=AzureConnectedMachineAgent'

    try {
        # Check if HtmlAgilityPack is already loaded
        if (-not ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'HtmlAgilityPack' })) {
            # Load HTML content into HtmlAgilityPack HTMLDocument
            Import-Module MSCatalog
            # Add-Type -Path "path\to\HtmlAgilityPack.dll" # Update this path to the location of HtmlAgilityPack.dll
        }

        # Fetch the search results page
        $searchResponse = Invoke-WebRequest -Uri $searchUrl
        $searchDoc = New-Object -TypeName HtmlAgilityPack.HtmlDocument
        $searchDoc.LoadHtml($searchResponse.Content)

        # Find all input elements with the class 'flatBlueButtonDownload'
        $updateIds = $searchDoc.DocumentNode.SelectNodes('//input[contains(@class, "flatBlueButtonDownload")]') |
            ForEach-Object { $_.Id } |
            Where-Object { $_ -ne $null }

        # Initialize results array
        $results = @()

        # Process each update ID
        foreach ($updateId in $updateIds) {
            $detailsUrl = "https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=$updateId"
            $detailsResponse = Invoke-WebRequest -Uri $detailsUrl
            $detailsDoc = New-Object -TypeName HtmlAgilityPack.HtmlDocument
            $detailsDoc.LoadHtml($detailsResponse.Content)

            # Parse the details page for KB Article Number and Title
            $kbArticle = $detailsDoc.DocumentNode.SelectSingleNode('//div[@id="kbDiv"]')?.InnerText.Trim()
            $title = $detailsDoc.DocumentNode.SelectSingleNode('//span[@id="ScopedViewHandler_titleText"]')?.InnerText.Trim()
            
             # Extract the version number from the title
            if ($title -match '(\d+\.\d+)') {
                $versionNumber = $matches[1]
            } else {
                $versionNumber = "Not Found"
            }

            # Extract just the number part from the text
            if ($kbArticle -match "\d+") {
                $kbArticleNumber = $matches[0]
            } else {
                $kbArticleNumber = "Not Found"
            }

            # Add to results
            $results += [PSCustomObject]@{
                Title = $title
                Version = $versionNumber
                KBArticle = $kbArticleNumber
            }
        }

        # Display results in table format
        $results | ConvertTo-Json

    } catch {
        Write-Host "An error occurred: $_"
    }
}

# Call the function to get the AzureConnectedMachineAgent version and KB Article numbers
Get-AzureConnectedMachineAgentVersion
