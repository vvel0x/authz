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
    user: ["read", "create", "upvote", "downvote"],
    moderator: ["update", "delete"],
  },
  comments: {
    user: ["create", "read"],
    admin: ["*"],
  },
};

// const authz = new Authz(authzConfig);
const authz = new Authz({ roles, resources, policies });

test("user can read posts", () => {
  expect(authz.check("user", "read", "posts")).toBe(true);
});

test("user cannot update posts", () => {
  expect(authz.check("user", "update", "posts")).toBe(false);
});

test("user can read comments", () => {
  expect(authz.check("user", "read", "comments")).toBe(true);
});

test("user cannot delete comments", () => {
  expect(authz.check("user", "delete", "comments")).toBe(false);
});

test("moderator can read posts", () => {
  expect(authz.check("moderator", "read", "posts")).toBe(true);
});

test("moderator can create posts", () => {
  expect(authz.check("moderator", "create", "posts")).toBe(true);
});

test("moderator can delete posts", () => {
  expect(authz.check("moderator", "delete", "posts")).toBe(true);
});

test("moderator cannot update comments", () => {
  expect(authz.check("moderator", "update", "comments")).toBe(false);
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

test("admin can can delete comments", () => {
  expect(authz.check("admin", "delete", "comments")).toBe(true);
});
