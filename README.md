# Metascan Email Relay (API v2)

This is an incoming email relay that scans all attachments using the metascan-online.com API.
The project is written in Python 3 and makes use of the standard SMTP email protocol, which in
turn allows it to function with virtually all email servers.

## Requirements
* Python3 (recommended 3.3+)
* An email Server (DNS, etc... is up to ones specific setup.)

## How it works
The email relay will sit in front of a "real" email server. When an email is recieved the
script will operate in this order:

1. Check for attachments
2. If there is NO attachment, send email.
3. If there is 1 or more attachments, parse them out.
4. Send to metascan-online.com service.
5. Attach scan results and remove infected files (if any).

## Configuration File (config.ini)
#### LISTEN_ON
    The IP or hostname the email relay is to be run on.
#### LISTEN_ON_PORT
    The port to run the email relay on.
#### MAIL_SERVER_DEST
    Set to the smart SMTP server you want to send email to.
#### MAIL_SERVER_PORT
    Set to the port the smart SMTP server is run on. If running on the same
    IP do not let it run on port 25.
    NOTE: Metascan Email Relay does all its listening on port 25 by default.
#### DOMAIN_ACCEPTED
    Make sure to put yourdomain.com with the @ symbol in front. So "@yourdomain.com"
#### MAX_EMAIL_SIZE
    The email size in MB to take. I would set it about 2-3 MB over what
    you really want. For example if you want emails that are only size 15MB set it
    for 18MB.
#### META_SCAN_API_LINK
    The Metascan link to use, should not need to change.
#### META_SCAN_API_KEY
    Your personal Metascan API key.
#### SCAN_LOOKUP_SLEEP_TIME
    How many seconds to wait in between polls to the scan server for results.
    Defaults to 5 seconds.
#### SCAN_MAX_LOOKUP_TIME
    The maximum time to wait for total polls, If takes more than 30 seconds
    will still send email with error message. Defaults to 30 seconds.

## Installation Instructions
I have tested the script on Ubuntu server 14.04 LTS (64-bit)

I originally had plans for an installation script, but each individual
server setup is usually unique per organization. So, instead I do plan 
to provide some basic setup instructions, and how to run the script as 
a service in ubuntu 64 bit specifically.
