permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
  && (resource.path == "" || resource.workspace_path == "/workspace")
};
