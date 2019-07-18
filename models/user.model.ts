export interface IAuthenticatorInfo {
    fmt: string;
    publicKey: string;
    counter: number;
    credID: string;
}

export interface IUserInfo {
    name: string;
    registered: boolean;
    id: string;
    authenticators: Array<IAuthenticatorInfo>;
}