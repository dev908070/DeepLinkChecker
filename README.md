# DeepLinkChecker

## Overview

**VerifyLink** is a Django project with an app named **URLsChecker** designed to ensure the integrity of LinkedIn posts by checking for potentially malicious or compromised external links. This tool identifies phishing links, malicious redirection, and sites with poor security hygiene by analyzing URLs in LinkedIn posts.

The `content_urls_check` API provides an endpoint that scans and analyzes external URLs within posts to detect any links that may pose a threat.

---

## Features

- Extracts and analyzes URLs from LinkedIn post content.
- Flags URLs that are unreachable or suspicious based on specific criteria.
- Integrates with VirusTotal API for enhanced threat detection.
- Provides JSON responses of flagged URLs for quick feedback.

## Installation

1. Clone the repository:

   ```git clone https://github.com/yourusername/VerifyLink.git ```
   
   ```cd VerifyLink ```

3. Install dependencies:

    ```pip install -r requirements.txt ```

4. Set up your VirusTotal API Key:
    - Sign up for a VirusTotal API Key.
    - Add your API key in the environment settings or replace it directly in the code (not recommended for security reasons).

5. Configure your Django settings:
    - Add the URLsChecker app to your INSTALLED_APPS in Django settings.
    - Ensure your database is configured.

6. Run migrations:

    ```python manage.py migrate ```

7. Start the server:

    ```python manage.py runserver ```
