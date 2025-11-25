# What is IAM (Identity & Access Management)
- IAM manages who you are (Identity) & what you can access.
- It ensures that right person gets the right access at the right time.
- It controls authentication and authorization.
- Typical IAM components are:
  - User accounts
  - Passwords, MFA, SSO
  - Role Based Access
  - Access approval workflow.
  - Identity lifecycle (Create -> Modify -> Delete user)

## Why IAM is used?
- IAM is used to control who can do what inside an organizations system in a scalable and secure way.
  1. To verify identity:  
     Every login - Employee, API, service - needs proof of who is accessing it.
  2. To prevent unauthorized access:  
     IAM ensures that users can only access the system they are supposed to nothing more.
  3. To maintain least privilage:
     People gets the minimum permissions needed for their job. No accidental admins. No unecessary access. No "Everyone has access to everything."
  4. To automate identity lifecycle:
     Create > Modify > Disable accounts automatically when employee's join/leave
  5. To ensure security policies:
     MFA, SSO, Password rules, device trust - all of it runs through IAM.

## Logic of IAM.
- IAM follows a simple but powerful chain of logic.

1. **Identity**: "Who is trying to enter?" Every user/service is assigned a unique identity.
2. **Authenticate**: "Prove you are who you claim" Password, MFA, SSO, Biometrics, Tokens.
3. **Authorize**: "What are you allowed to do" IAM checks your role & permission (RBAC/ABAC).
4. **Audit**: "Record what you did" Logs are kept for security, compliance and incident response.
