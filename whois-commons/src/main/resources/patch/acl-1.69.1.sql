-- http://jira.apnic.net/browse/WHOIS-91
ALTER TABLE acl_limit
ADD query_limit INT DEFAULT '-1' NOT NULL AFTER daily_limit;
TRUNCATE version;
INSERT INTO version VALUES ('acl-1.69.1');
