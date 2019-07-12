export let database: {[id: string] : userInfo} = {}

export interface authenticatorInfo {
    fmt: string;
    publicKey: string;
    counter: number;
    credID: string;
}

export interface userInfo {
    name: string;
    registered: boolean;
    id: string;
    authenticators: Array<authenticatorInfo>;
}
