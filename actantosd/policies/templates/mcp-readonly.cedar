permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false &&
  (
    action == Action::"ReadFile" ||
    action == Action::"ListFiles"
  )
};
