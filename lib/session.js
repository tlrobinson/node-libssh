const EventEmitter = require('events').EventEmitter
    , util         = require('util')
    , Channel      = require('./channel')

function Session (server, session) {
  this._session = session
  this._server  = server

  session.onMessage = function (message) {
    if (this._server._options.debug)
      console.log('session message', message)
    if (message.type == 'auth')
      return this.emit('auth', message)
    // else handle default.. probably should pass this on
    message.replyDefault()
  }.bind(this)

  session.onNewChannel = function (channel) {
    this.emit('channel', new Channel(this._server, channel))
    setImmediate(function () {
      // why setImmediate?? WHO KNOWS! something to do with the
      // timing of starting polling vs setting up the callbacks
      channel.start()
    })
  }.bind(this)

  session.onGlobalRequest = function (message) {
    if (this._server._options.debug)
      console.log('global request', message)

    // if no "tcpipforward" listeners exist return failure
    // otherwise assume success unless listener explicitly sends "replyDefault"
    if (this.listeners('tcpipforward').length === 0)
      message.replyDefault()

    // tcpipforward, canceltcpipforward, etc
    return this.emit(message.subtype, message)
  }.bind(this)

  EventEmitter.call(this)
}

util.inherits(Session, EventEmitter)

Session.prototype.close = function () {
  this._session.close()
  return this
}

Session.prototype.setAuthMethods = function (methods) {
  this._session.setAuthMethods(methods)
  return this
}

Session.prototype.openReverseForward = function (remotehost, remoteport, sourcehost, localport) {
  var channel = this._session.openReverseForward(remotehost, remoteport, sourcehost, localport)
  return new Channel(this._server, channel)
}

module.exports = Session
