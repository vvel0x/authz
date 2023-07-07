export type RoleConfig = Readonly<Record<string, { inherits?: string[] }>>;
export type ResourceConfig = Record<string, readonly string[]>;

export type PolicyConfig<
  T extends ResourceConfig,
  U extends RoleConfig,
> = Partial<{
  [Resource in keyof T]: Partial<{
    [Role in keyof U]: (T[Resource][number] | "*")[];
  }>;
}>;

type AuthzConfig<T extends RoleConfig, U extends ResourceConfig> = {
  roles: T;
  resources: U;
  policies: PolicyConfig<U, T>;
};

class Authz<T extends RoleConfig, U extends ResourceConfig> {
  private readonly roles: T;
  private readonly resources: U;
  private readonly policies: PolicyConfig<U, T>;

  constructor(config: AuthzConfig<T, U>) {
    this.roles = config.roles;
    this.resources = config.resources;
    this.policies = config.policies;
  }

  check(role: keyof T, action: string, resource: keyof U): boolean {
    const roleConfig = this.roles[role];
    const resourceConfig = this.resources[resource];
    const policy = this.policies[resource]?.[role];

    if (roleConfig?.inherits?.some((r) => this.check(r, action, resource)))
      return true;

    if (!roleConfig || !resourceConfig || !policy) return false;

    if (policy.includes("*")) {
      return true;
    }

    return policy.includes(action);
  }
}

export default Authz;
