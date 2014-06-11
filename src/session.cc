/* Copyright (c) 2013 Rod Vagg
 * MIT +no-false-attribs License <https://github.com/rvagg/node-ssh/blob/master/LICENSE>
 */
#include <node.h>
#include <nan.h>
#include <iostream>
#include <libssh/server.h>
#include <libssh/keys.h>
#include <libssh/socket.h>
#include <libssh/poll.h>
#include <libssh/messages.h>
#include <string.h>
#include "session.h"
#include "message.h"

namespace nssh {

static v8::Persistent<v8::FunctionTemplate> session_constructor;

void Session::OnError (std::string err) {
  //TODO:
  if (NSSH_DEBUG)
    std::cout << "ERROR: " << err << std::endl;
}

void Session::OnMessage (v8::Handle<v8::Object> message) {
  NanScope();

  v8::Local<v8::Value> callback = NanObjectWrapHandle(this)
      ->Get(NanSymbol("onMessage"));

  if (callback->IsFunction()) {
    v8::TryCatch try_catch;
    v8::Handle<v8::Value> argv[] = { message };
    callback.As<v8::Function>()->Call(NanObjectWrapHandle(this), 1, argv);

    if (try_catch.HasCaught())
      node::FatalException(try_catch);
  }
}

void Session::OnNewChannel (v8::Handle<v8::Object> channel) {
  NanScope();

  v8::Local<v8::Value> callback = NanObjectWrapHandle(this)
      ->Get(NanSymbol("onNewChannel"));

  if (callback->IsFunction()) {
    v8::TryCatch try_catch;
    v8::Handle<v8::Value> argv[] = { channel };
    callback.As<v8::Function>()->Call(NanObjectWrapHandle(this), 1, argv);

    if (try_catch.HasCaught())
      node::FatalException(try_catch);
  }
}

void Session::OnGlobalRequest (v8::Handle<v8::Object> message) {
  NanScope();

  v8::Local<v8::Value> callback = NanObjectWrapHandle(this)
      ->Get(NanSymbol("onGlobalRequest"));

  if (callback->IsFunction()) {
    v8::TryCatch try_catch;
    v8::Handle<v8::Value> argv[] = { message };
    callback.As<v8::Function>()->Call(NanObjectWrapHandle(this), 1, argv);

    if (try_catch.HasCaught())
      node::FatalException(try_catch);
  }
}

void Session::OnClose () {
  NanScope();

  v8::Local<v8::Value> callback = NanObjectWrapHandle(this)
      ->Get(NanSymbol("onClose"));

  if (callback->IsFunction()) {
    v8::TryCatch try_catch;
    v8::Handle<v8::Value> argv[] = { };
    callback.As<v8::Function>()->Call(NanObjectWrapHandle(this), 0, argv);

    if (try_catch.HasCaught())
      node::FatalException(try_catch);
  }
}

void Session::ChannelClosedCallback (Channel *channel, void *userData) {
  Session* s = static_cast<Session*>(userData);

  if (NSSH_DEBUG)
    std::cout << "ChannelClosedCallback!\n";

  std::vector<Channel*>::iterator it = s->channels.begin();
  while (it != s->channels.end()) {
    if ((*it)->IsChannel(channel->channel)) {
      if (NSSH_DEBUG)
        std::cout << "Removed " << (*it)->myid << std::endl;
      s->channels.erase(it);
      if (NSSH_DEBUG)
        std::cout << "Found and removed channel from list\n";
      break;
    }
    ++it;
  }

  /*
  if (s->channels.size() == 0) {
    if (NSSH_DEBUG)
      std::cout << "!!!!!!!!!!!!!!!!!!!! CLOSING, NO MORE CHANNELS !!!!!!!!!!!!!!!!\n";
    s->Close();
  }
  */
}

void Session::SocketPollCallback (uv_poll_t* handle, int status, int events) {
  NanScope();

  Session* s = static_cast<Session*>(handle->data);

  if (NSSH_DEBUG) {
    std::cout << "SocketPollCallback... " << status << ", " << events
      << ", " << ssh_get_status(s->session)
      << std::endl;
  }

  // doesn't suit async handling: ssh_execute_message_callbacks(s->session);

  if (!s->active)
    return;

  ssh_message message;
  int type;
  int subtype;

  while (true) {
    if (NSSH_DEBUG)
      std::cout << "checking for message...\n";

    message = ssh_message_get(s->session);

    if (NSSH_DEBUG)
      std::cout << "message loop " << (!message) << " status=" << ssh_get_status(s->session) << std::endl;

    //NOTE: this is patched in my local version to check session->session_state
    if (ssh_get_status(s->session) & SSH_CLOSED_ERROR) {
      if (NSSH_DEBUG)
        std::cout << "session status is SSH_CLOSED_ERROR, closing\n";
      return s->Close();
    }

    if (!message)
      break;

    type = ssh_message_type(message);
    subtype = ssh_message_subtype(message);

    if (NSSH_DEBUG)
      std::cout << "message, type = " << type << ", subtype = " << subtype
        << std::endl;

    if (type == SSH_REQUEST_CHANNEL_OPEN && subtype == SSH_CHANNEL_SESSION) {

      if (NSSH_DEBUG)
        std::cout << "New Channel\n";

      v8::Handle<v8::Object> channel = Channel::NewInstance(
          s->session
        , ssh_message_channel_request_open_reply_accept(message)
        , s->ChannelClosedCallback
        , s
      );

      s->channels.push_back(node::ObjectWrap::Unwrap<Channel>(channel));
      if (NSSH_DEBUG)
        std::cout << "New channel " << node::ObjectWrap::Unwrap<Channel>(channel)->myid << std::endl;
      s->OnNewChannel(channel);

      ssh_message_free(message);
    } else {
      if (type == SSH_REQUEST_CHANNEL && subtype) {
        if (NSSH_DEBUG)
          std::cout << "*****************************" << s->channels.size() << " channels\n";
        std::vector<Channel*>::reverse_iterator it = s->channels.rbegin();
        while (it != s->channels.rend()) {
          if (NSSH_DEBUG)
            std::cout << "*************** IT1 NEXT ************** " << (*it)->myid << std::endl;
          if ((*it)->IsChannel(ssh_message_channel_request_channel(message))) {
            (*it)->OnMessage(Message::NewInstance(s->session, *it, message));
            break;
          }
          ++it;
        }
        if (NSSH_DEBUG)
          std::cout << "*****************************\n";
        ssh_message_free(message);
      } else {
        v8::Handle<v8::Object> mess =
            Message::NewInstance(s->session, NULL, message);
        s->OnMessage(mess);
        // freed on ~Message()
      }
    }
  }

  bool channelData = false;
  if (NSSH_DEBUG)
    std::cout << "***************************** " << s->channels.size() << " channels\n";
  std::vector<Channel*>::reverse_iterator it = s->channels.rbegin();
  while (it != s->channels.rend()) {
    if (NSSH_DEBUG)
      std::cout << "*************** IT2 NEXT ************** " << (*it)->myid << std::endl;
    if ((*it)->TryRead()) {
      channelData = true;
      break;
    }
    ++it;
  }
  if (NSSH_DEBUG)
    std::cout << "*****************************\n";

  if (NSSH_DEBUG)
    std::cout << "Channel Data: " << (channelData ? "yes" : "no") << std::endl;
}

Session::Session () {
  active = false;
}

Session::~Session () {
  Close();
  ssh_free(session);
  //delete callbacks;
}

void Session::Close () {
  active = false;
  uv_poll_stop(poll_handle);
  //delete poll_handle;
  ssh_set_callbacks(session, 0);
  ssh_set_message_callback(session, 0, 0);
  //TODO: investigate whether this is needed in some way, it doesn't
  // work when you have data in the pipe when called:
  //ssh_disconnect(session);
  if (NSSH_DEBUG)
    std::cout << "Stopped polling session, " << channels.size() << " channels open\n";

  OnClose();
}

void Session::SetAuthMethods (int methods) {
  ssh_set_auth_methods(session, methods);
  if (NSSH_DEBUG)
    std::cout << "Changed auth methods to " << methods << "\n";
}

ssh_channel Session::OpenReverseForward(const char *remotehost, int remoteport,
    const char *sourcehost, int localport) {

  if (NSSH_DEBUG)
    std::cout << "ssh_channel_open_reverse_forward" << std::endl;

  ssh_channel chan;
  int rc;

  chan = ssh_channel_new(session);
  if (chan == NULL) {
    return NULL;
  }

  if (sourcehost == NULL) sourcehost = "";

  // TODO: make this asynchronous?
  do {
    rc = ssh_channel_open_reverse_forward(chan, remotehost, remoteport, sourcehost, localport);
  } while (rc == SSH_AGAIN);

  if (rc < 0) {
    ssh_channel_free(chan);
    chan = NULL;
  }

  return chan;
}

// a client callback (I think)
int Session::AuthCallback (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata) {

  if (NSSH_DEBUG)
    std::cout << "Session::AuthCallback! " << std::endl;
  return 0;
}

void Session::LogCallback (ssh_session session, int priority,
    const char *message, void *userdata) {

  if (NSSH_DEBUG)
    std::cout << "Session::LogCallback! " << priority << ", " << message
      << std::endl;
}

// not sure if this gets used
void Session::GlobalRequestCallback (ssh_session session, ssh_message message,
    void *userData) {

  int type = ssh_message_type(message);
  int subtype = ssh_message_subtype(message);

  if (NSSH_DEBUG)
    std::cout << "Session::GlobalRequestCallback! " << type << ", " << subtype << std::endl;

  Session* s = static_cast<Session*>(userData);
  if (type == SSH_REQUEST_GLOBAL) {
    s->OnGlobalRequest(Message::NewInstance(s->session, NULL, message));
  }
}

// not used as far as I can tell
int Session::MessageCallback (ssh_session session, ssh_message message, void *data) {
  if (NSSH_DEBUG)
    std::cout << "Session::MessageCallback! " << std::endl;

  return 1;
}

void Session::StatusCallback (void *userdata, float status) {
  if (NSSH_DEBUG)
    std::cout << "Session::StatusCallback! " << status << std::endl;
}


void Session::Start () {

  callbacks = new ssh_callbacks_struct;
  callbacks->auth_function = NULL; // Session::AuthCallback;
  callbacks->log_function = NULL; // Session::LogCallback;
  callbacks->global_request_function = Session::GlobalRequestCallback;
  callbacks->connect_status_function = NULL; // Session::StatusCallback;
  callbacks->userdata = this;
  ssh_callbacks_init(callbacks);
  ssh_set_callbacks(session, callbacks);
  // ssh_set_message_callback(session, Session::MessageCallback, this);

  ssh_options_set(session, SSH_OPTIONS_TIMEOUT, "0");
  ssh_options_set(session, SSH_OPTIONS_TIMEOUT_USEC, "1");
  ssh_set_blocking(session, 0);

  //TODO: do this async
  if (ssh_handle_key_exchange(session)) {
    std::string err("Key exchange error: ");
    err.append(ssh_get_error(session));
    OnError(err);
  }

  active = true;
  poll_handle = new uv_poll_t;
  uv_os_sock_t socket = ssh_get_fd(session);
  poll_handle->data = this;
  uv_poll_init_socket(uv_default_loop(), poll_handle, socket);
  uv_poll_start(poll_handle, UV_READABLE, SocketPollCallback);

  if (NSSH_DEBUG)
    std::cout << "polling started\n";
}

void Session::Init () {
  NanScope();

  v8::Local<v8::FunctionTemplate> tpl = v8::FunctionTemplate::New(New);
  NanAssignPersistent(v8::FunctionTemplate, session_constructor, tpl);
  tpl->SetClassName(NanSymbol("Session"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  NODE_SET_PROTOTYPE_METHOD(tpl, "close", Close);
  NODE_SET_PROTOTYPE_METHOD(tpl, "setAuthMethods", SetAuthMethods);
  NODE_SET_PROTOTYPE_METHOD(tpl, "openReverseForward", OpenReverseForward);
}

v8::Handle<v8::Object> Session::NewInstance (ssh_session session) {
  NanScope();

  v8::Local<v8::Object> instance;
  v8::Local<v8::FunctionTemplate> constructorHandle =
      NanPersistentToLocal(session_constructor);
  instance = constructorHandle->GetFunction()->NewInstance(0, NULL);
  Session *s = ObjectWrap::Unwrap<Session>(instance);
  s->session = session;
  NanAssignPersistent(v8::Object, s->persistentHandle, instance);

  if (NSSH_DEBUG)
    std::cout << "returning new Session::New()\n";
  return scope.Close(instance);
}

NAN_METHOD(Session::New) {
  NanScope();

  Session* obj = new Session();
  obj->Wrap(args.This());
  if (NSSH_DEBUG)
    std::cout << "Session::New()" << std::endl;

  NanReturnValue(args.This());
}

NAN_METHOD(Session::Close) {
  NanScope();

  if (NSSH_DEBUG)
    std::cout << "Session::Close()" << std::endl;

  Session *s = ObjectWrap::Unwrap<Session>(args.This());
  s->Close();
  NanDispose(s->persistentHandle);

  NanReturnUndefined();
}

NAN_METHOD(Session::SetAuthMethods) {
  NanScope();

  Session *s = ObjectWrap::Unwrap<Session>(args.This());
  s->SetAuthMethods(args[0]->Int32Value());

  NanReturnUndefined();
}

NAN_METHOD(Session::OpenReverseForward) {
  NanScope();

  char *remotehost = NULL, *sourcehost = NULL;
  int remoteport = 0, localport = 0;

  if (args.Length() >= 1 && args[0]->IsString()) remotehost = NanFromV8String(args[0]);
  if (args.Length() >= 2 && args[1]->IsNumber()) remoteport = args[1]->Int32Value();
  if (args.Length() >= 3 && args[2]->IsString()) sourcehost = NanFromV8String(args[2]);
  if (args.Length() >= 4 && args[3]->IsNumber()) localport = args[3]->Int32Value();

  Session *s = ObjectWrap::Unwrap<Session>(args.This());

  ssh_message message = ssh_message_get(s->session);

  if (NSSH_DEBUG)
    std::cout << "message loop " << (!message) << " status=" << ssh_get_status(s->session) << std::endl;

  ssh_channel chan = s->OpenReverseForward(remotehost, remoteport, sourcehost, localport);
  if (!chan) {
    NanReturnNull();
  }

  v8::Handle<v8::Object> channel = Channel::NewInstance(
      s->session
    , chan
    , ChannelClosedCallback
    , s
  );

  s->channels.push_back(node::ObjectWrap::Unwrap<Channel>(channel));
  if (NSSH_DEBUG)
    std::cout << "OpenReverseForward channel" << node::ObjectWrap::Unwrap<Channel>(channel)->myid << std::endl;
  s->OnNewChannel(channel);

  NanReturnValue(channel);
}

} // namespace nssh
