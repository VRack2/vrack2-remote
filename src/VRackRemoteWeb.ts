import VRackRemote from './VRackRemote';

export default class VRackRemoteWeb extends VRackRemote{
    host: string
    ws?: WebSocket
    constructor(host = 'ws://localhost:4044', key = 'default', privateKey = ''){
        super(key, privateKey)
        this.host = host
    }

    connect(){
        return new Promise((resolve, reject)=>{
            if (this.connected === true) this.transportDisconnect()
            this.connection = true
            this.emit('connection')
            try {
                this.ws = new WebSocket(this.host)
            } catch (error) { reject(error); return }

            // Owerride
            this.transportSend = (data: string) => {
                this.ws?.send(data)
            }

            // Owerride
            this.transportDisconnect = () => { 
                this.ws?.close() 
            }

            this.ws.onopen = () => {
                this.transportOnOpen()
                resolve('success')
            }

            this.ws.onerror = (error) =>{
                this.transportOnError(new Error('Websocket error'))
            }

            this.ws.onclose = () => {
                this.transportOnClose()
                this.ws = undefined
                reject(new Error('Connection closed'))
            }
            this.ws.onmessage = (evt) => {
                this.transportOnMessage(evt.data)
            }
        })
    }

    disconnect(){
        this.ws?.close()
    }
}