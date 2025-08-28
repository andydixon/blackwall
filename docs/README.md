# Blackwall SSO

PSR-4 PHP SSO module with project-level privileges under namespace `\\andydixon\\blackwall`.

- OAuth2/OpenID Connect style login, callback, logout
- Projects table (UUID id), user->project privilege mapping
- Admin UI gated by membership of project "SSO Administration" with privilege=1
- Project "SSO Administration" auto-created on first admin access; seed initial admins by inserting into user_projects for that project
