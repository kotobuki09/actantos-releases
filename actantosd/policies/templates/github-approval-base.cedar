permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
};
