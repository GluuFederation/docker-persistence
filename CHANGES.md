# Changelog

Here you can see an overview of changes between each release.

## Version 4.0.1_07

Released on March 2nd, 2020.

* Fetched Passport RS cert alias.

## Version 4.0.1_06

Released on December 27th, 2019.

* Added environment to enable SCIM (test mode and UMA mode) upon container deployment.

## Version 4.0.1_05

Released on December 1st, 2019.

* Added environment to enable oxTrust API (test mode and UMA mode) upon container deployment.
* Added environment to activate Passport, SAML, Radius, and Casa upon container deployment.

## Version 4.0.1_04

Released on November 19th, 2019.

* Removed several indexes for Couchbase due to performance degradation.

## Version 4.0.1_03

Released on November 15th, 2019.

* Added missing indexes for Couchbase.
* Added performance optimization for oxAuth.

## Version 4.0.1_02

Released on November 14th, 2019.

* Upgraded `pygluu-containerlib` to show connection issue with Couchbase explicitly.

## Version 4.0.1_01

Released on November 1st, 2019.

* Upgraded to Gluu Server 4.0.1.

## Version 4.0.0_01

Released on October 22nd, 2019.

* Introduced as a way to generate initial data for Gluu Server 4.0. This replaces the auto-generate data feature found in previous OpenDJ v3 releases.
