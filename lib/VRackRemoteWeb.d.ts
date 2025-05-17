import VRackRemote from './VRackRemote';
export default class VRackRemoteWeb extends VRackRemote {
    host: string;
    ws?: WebSocket;
    constructor(host?: string, key?: string, privateKey?: string);
    connect(): Promise<unknown>;
    disconnect(): void;
}
