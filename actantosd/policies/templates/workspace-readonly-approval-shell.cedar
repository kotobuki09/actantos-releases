permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false &&
  (
    action in [
      Action::"ReadFile",
      Action::"ListDirectory",
      Action::"SearchWorkspace"
    ] ||
    action == Action::"ExecuteShellCommand"
  )
};
