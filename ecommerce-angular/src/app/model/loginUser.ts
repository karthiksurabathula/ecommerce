export class user {
    username: string;
    accountNonLocked: boolean;
    enabled: boolean;
}

export class userResponse {
  indicator: string;
  message: string;
  users: Array<user>;
}

export class userResponse1 {
  indicator: string;
  message: string;
  user: user;
}

export interface userResponse {
    userResponse: userResponse;
}
