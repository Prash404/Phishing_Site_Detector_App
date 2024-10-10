# Phishing Site Detector

## Description

The **Phishing Site Detector** is a Python application designed to help users assess the safety of a given URL. The application utilizes various libraries to check for SSL certificate validity, domain age, and other indicators of phishing behavior. The result is a suspicion score that helps determine whether a site is likely safe or potentially malicious.

## Features

- **URL Validation:** Checks if the provided URL exists.
- **SSL Certificate Retrieval:** Retrieves and validates the SSL certificate from the website.
- **Domain Age Check:** Uses WHOIS data to determine the age of the domain.
- **Certificate Revocation List (CRL) Check:** Verifies if the SSL certificate has been revoked.
- **Suspicion Scoring:** Calculates a suspicion score based on the domain's age and SSL certificate details, where a score between (0,1) suggests safety.
- **Detailed Information Display:** Shows additional details regarding the SSL certificate and domain age.

## Installation

1. **Prerequisites:**
   - Ensure you have Python 3.x installed on your machine.

2. **Install Required Libraries:**
   - You need to install the following Python libraries given in the requirements file.
   
3. **Download Files:**
   - Download the phishing_detector.py script.
   - Include a PNG image named phish.png in the same directory for the application icon.

## Usage

1. **Run the Application:** Launch the application by executing the Python script: python phishing_detector.py

2. **Enter a URL:** In the application interface, input the URL you want to check.

3. **Check the URL:** Click the "Check URL" button. The application will analyze the URL and provide feedback on its safety along with a suspicion score.

4. **View Additional Details:** Click the "Additional Details" button to view more information about the SSL certificate and domain:
   - Issued To
   - Issued By
   - Valid From
   - Valid Until
   - Domain Creation Date
   - Domain Age in days

5. **Interpreting the Suspicion Score:**
   - A score between (0,1) indicates that the site is likely safe.
   - A score 0,1,above 1,below 0 suggests that the site may be suspicious or a phishing attempt.

## Files

- phishing_detector.py: The main Python script containing the application logic.
- phish.png: Image file used as the application icon.

## Dependencies

- Tkinter: For creating the graphical user interface.
- requests: For making HTTP requests.
- whois: For retrieving domain information.
- cryptography: For handling SSL certificate verification and parsing.
- OpenSSL: For managing SSL certificates in binary form.
