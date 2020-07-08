# Carbon Black - Checkpoint  Connector

The Checkpoint  connector submits binaries collected by Carbon Black to Checkpoint 
for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black server. The feed will then tag any binaries executed on your
endpoints identified as malware by Checkpoint . Only binaries submitted by the connector
for analysis will be included in the generated Intelligence Feed.

This connector submits full binaries by default, and binaries may be shared with Checkpoint based on the configuration. 

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-checkpoint-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/checkpoint/connector.conf.example` file to
`/etc/cb/integrations/checkpoint/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for Checkpoint  into the configuration file: place your checkpoint api key in `checkpoint_api_key` in the 
`/etc/cb/integrations/checkpoint/connector.conf` file.

Adjust the 'checkpoint_url' variable in the connector configuration file to use the hostname/ip address of the Checkpoint cloud service  to be used. 
The default is https://te.checkpoint.com. 

Any errors will be logged into `/var/log/cb/integrations/checkpoint/checkpoint.log`.

## Troubleshooting

If you suspect a problem, please first look at the Checkpoint  connector logs found here:
`/var/log/cb/integrations/checkpoint/checkpoint.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-checkpoint-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/checkpoint/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-checkpoint-connector start`

## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
