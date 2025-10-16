Known Issues
############

The following is a list of known issues in Suricata 7.0.

* When an IKE message contains multiple attributes with the same key,
  only the first will be logged to avoid producing invalid JSON, or
  introducing a logging format change. See
  https://redmine.openinfosecfoundation.org/issues/7923.
