/* Copyright (c) 2013 Rod Vagg
 * MIT +no-false-attribs License <https://github.com/rvagg/node-ssh/blob/master/LICENSE>
 */

#ifndef NSSH_SESSION_H
#define NSSH_SESSION_H

#include <node.h>
#include <node_buffer.h>
#include <libssh/server.h>
#include <libssh/poll.h>
#include <string>
#include <vector>
#include <nan.h>

#include "nssh.h"
#include "channel.h"

namespace nssh {

class Session : public node::ObjectWrap {
 public:
  static void Init ();
  static v8::Handle<v8::Object> NewInstance (ssh_session session);

  Session ();
  ~Session ();

  void Start ();
  void Close ();
  void SetAuthMethods (int methods);
  ssh_channel OpenReverseForward (const char *remotehost, int remoteport, const char *sourcehost, int localport);

  void OnMessage (v8::Handle<v8::Object> message);
  void OnNewChannel (v8::Handle<v8::Object> channel);
  void OnError (std::string error);
  void OnGlobalRequest (v8::Handle<v8::Object> message);
  void OnClose ();

 private:
  static void SocketPollCallback (uv_poll_t* handle, int status, int events);
  static void ChannelClosedCallback (Channel *channel, void *user);
  static int MessageCallback (ssh_session session, ssh_message message, void *data);
  static int AuthCallback (const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata);
  static void LogCallback (ssh_session session, int priority, const char *message, void *userdata);
  static void GlobalRequestCallback (ssh_session session, ssh_message message, void *userData);
  static void StatusCallback (void *userdata, float status);

  ssh_session session;
  uv_poll_t *poll_handle;
  ssh_callbacks_struct *callbacks;
  v8::Persistent<v8::Object> persistentHandle;
  bool active;

  std::vector<Channel*> channels;

  static NAN_METHOD(New);
  static NAN_METHOD(Close);
  static NAN_METHOD(SetAuthMethods);
  static NAN_METHOD(OpenReverseForward);
};

} // namespace nssh

#endif
