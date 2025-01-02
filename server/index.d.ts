import "express-session";

declare module "express-session" {
  interface SessionData {
    currentChallenge?: string;
    username?: string;
  }
}
