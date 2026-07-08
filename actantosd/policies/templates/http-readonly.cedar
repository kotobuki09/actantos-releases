permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false &&
  action in [
    Action::"HttpGet",
    Action::"HttpHead"
  ]
};
