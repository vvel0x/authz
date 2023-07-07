import Authz, { type RoleConfig, type PolicyConfig } from "../index";

const roles: RoleConfig = {
  user: {},
  moderator: { inherits: ["user"] },
  admin: { inherits: ["user", "moderator"] },
};

const resources = {
  posts: ["read", "create", "update", "delete", "upvote", "downvote"],
  comments: ["read", "create", "update", "delete"],
} as const;

const policies: PolicyConfig<typeof resources, typeof roles> = {
  posts: {
    user: ["read", "upvote", "downvote"],
    moderator: ["create", "update"],
    admin: ["delete"],
  },
  comments: {
    user: ["read"],
    admin: ["*"],
  },
};

// const authz = new Authz(authzConfig);
const authz = new Authz({ roles, resources, policies });

test("user can read posts", () => {
  expect(authz.check("user", "read", "posts")).toBe(true);
});

test("user cannot create posts", () => {
  expect(authz.check("user", "create", "posts")).toBe(false);
});

test("user cannot delete posts", () => {
  expect(authz.check("user", "delete", "posts")).toBe(false);
});

test("user cannot update posts", () => {
  expect(authz.check("user", "update", "posts")).toBe(false);
});

test("user can upvote posts", () => {
  expect(authz.check("user", "upvote", "posts")).toBe(true);
});

test("user can read comments", () => {
  expect(authz.check("user", "read", "comments")).toBe(true);
});

test("user cannot create comments", () => {
  expect(authz.check("user", "create", "comments")).toBe(false);
});

test("moderator can read posts", () => {
  expect(authz.check("moderator", "read", "posts")).toBe(true);
});

test("moderator can create posts", () => {
  expect(authz.check("moderator", "create", "posts")).toBe(true);
});

test("moderator cannot delete posts", () => {
  expect(authz.check("moderator", "delete", "posts")).toBe(false);
});

test("admin can read posts", () => {
  expect(authz.check("admin", "read", "posts")).toBe(true);
});

test("admin can create posts", () => {
  expect(authz.check("admin", "create", "posts")).toBe(true);
});

test("admin can delete posts", () => {
  expect(authz.check("admin", "delete", "posts")).toBe(true);
});

test("admin can read comments", () => {
  expect(authz.check("admin", "read", "comments")).toBe(true);
});
