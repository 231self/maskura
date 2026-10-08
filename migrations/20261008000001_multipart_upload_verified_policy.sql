-- Slice 3 / P4.1h: freeze the policy-gate verdict admitted at MultipartCreate
-- on the staged upload so later multipart operations can re-verify it.
alter table multipart_uploads add column if not exists verified_policy jsonb;
