UPDATE policy_bundles
SET source_hash = '5c8533bd835a317b9191d940ea78ef0c3a2f641a45add6affe6897d046989f1a',
    source_text = 'permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
};'
WHERE tenant_id = 't_demo'
  AND id = '33333333-3333-3333-3333-333333333333'
  AND source_text = 'fake';
