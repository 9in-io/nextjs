import type { User } from "@9in-io/sdk";

export type { User };

/** The signed-in user as your app sees it. It holds no tokens, so you can pass it to Client Components. */
export interface Session {
  user: User;
}
