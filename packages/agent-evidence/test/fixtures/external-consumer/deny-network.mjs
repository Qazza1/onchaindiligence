const denied = () => {
  throw new Error('network access is forbidden in the offline consumer fixture')
}

globalThis.fetch = denied

const { default: net } = await import('node:net')
const { default: tls } = await import('node:tls')
const { default: http } = await import('node:http')
const { default: https } = await import('node:https')

net.Socket.prototype.connect = denied
tls.TLSSocket.prototype.connect = denied
http.request = denied
http.get = denied
https.request = denied
https.get = denied
