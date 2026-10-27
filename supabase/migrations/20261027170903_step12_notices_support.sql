-- Independent Step 12 notice support. No instructor, notice, or auth user is seeded.
create table if not exists public.vault_instructors (
  user_id uuid primary key
);

create table if not exists public.vault_notices (
  public_id uuid primary key default extensions.gen_random_uuid(),
  title text not null,
  content text
);

alter table public.vault_instructors enable row level security;
alter table public.vault_notices enable row level security;

revoke all on table public.vault_instructors, public.vault_notices
from public, anon, authenticated, service_role;
grant usage on schema public to service_role;
grant select, update on table public.vault_notices to service_role;
grant select on table public.vault_instructors to service_role;

notify pgrst, 'reload schema';
