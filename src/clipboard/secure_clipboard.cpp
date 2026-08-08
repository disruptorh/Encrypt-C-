#include "clipboard/secure_clipboard.hpp"

#include <cstring>

#include <sys/select.h>

#include <X11/Xatom.h>

namespace clipboard {

namespace {
constexpr int kTargetsIndex = 0;
constexpr int kUtf8Index = 1;
constexpr int kStringIndex = 2;
constexpr int kTextIndex = 3;
constexpr int kTimestampIndex = 4;
constexpr int kTargetCount = 5;
}  // namespace

bool secure_clipboard::init() {
  if (active_) return true;

  dpy_ = XOpenDisplay(nullptr);
  if (dpy_ == nullptr) {
    active_ = false;
    return false;
  }

  win_ = XCreateSimpleWindow(dpy_, DefaultRootWindow(dpy_), 0, 0, 1, 1, 0, 0, 0);
  clip_atom_ = XInternAtom(dpy_, "CLIPBOARD", False);
  utf8_atom_ = XInternAtom(dpy_, "UTF8_STRING", False);
  string_atom_ = XInternAtom(dpy_, "STRING", False);
  text_atom_ = XInternAtom(dpy_, "TEXT", False);
  targets_atom_ = XInternAtom(dpy_, "TARGETS", False);
  ts_atom_ = XInternAtom(dpy_, "_SECURE_CLIPBOARD_TS", False);
  // Needed for current_server_time() to receive the PropertyNotify event that
  // carries the server timestamp.
  XSelectInput(dpy_, win_, PropertyChangeMask);
  active_ = true;
  return true;
}

void secure_clipboard::shutdown() {
  clear_now();
  if (dpy_ != nullptr) {
    if (win_ != 0) XDestroyWindow(dpy_, win_);
    XCloseDisplay(dpy_);
  }
  dpy_ = nullptr;
  win_ = 0;
  active_ = false;
}

void secure_clipboard::set_text(const char* text, std::size_t len) {
  if (!active_) return;
  // Wipe anything previously held before taking the new content.
  buffer_.zero();
  buffer_.resize(len + 1, /*preserve=*/false);
  if (len != 0) std::memcpy(buffer_.data(), text, len);
  buffer_.data()[len] = '\0';
  len_ = len;
  claim_selection();
}

void secure_clipboard::claim_selection() {
  // ICCCM: claim the selection with a real server timestamp rather than
  // CurrentTime. With CurrentTime a concurrent X11 client could win the
  // selection between our request and the ownership check below; a timestamp
  // derived from the server's own clock closes that race.
  const ::Time ts = current_server_time();
  XSetSelectionOwner(dpy_, clip_atom_, win_, ts);
  owned_ = (XGetSelectionOwner(dpy_, clip_atom_) == win_);
  expires_at_ms_ = 0;  // countdown started by poll() once ownership is settled
}

::Time secure_clipboard::current_server_time() {
  // Standard ICCCM technique: perform a zero-length property change on our own
  // window; the server stamps the resulting PropertyNotify with the current
  // time. Bounded wait so a wedged server degrades to CurrentTime instead of
  // blocking the UI indefinitely.
  XChangeProperty(dpy_, win_, ts_atom_, XA_INTEGER, 32, PropModeReplace,
                  nullptr, 0);
  XFlush(dpy_);
  const int fd = ConnectionNumber(dpy_);
  for (int i = 0; i < 10; ++i) {
    while (XPending(dpy_) > 0) {
      XEvent ev;
      XNextEvent(dpy_, &ev);
      if (ev.type == PropertyNotify && ev.xproperty.window == win_ &&
          ev.xproperty.atom == ts_atom_) {
        return ev.xproperty.time;
      }
      // Selection events must not be dropped while waiting.
      handle_event(ev);
    }
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 2000;  // 2 ms
    if (select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) break;
  }
  return CurrentTime;
}

void secure_clipboard::clear_now() {
  if (dpy_ != nullptr && owned_) {
    XSetSelectionOwner(dpy_, clip_atom_, None, CurrentTime);
    XFlush(dpy_);
  }
  owned_ = false;
  buffer_.zero();
  len_ = 0;
  expires_at_ms_ = 0;
}

void secure_clipboard::poll(std::uint64_t now_ms) {
  if (!active_) return;

  // Auto-clear timeout: start the countdown once ownership is established.
  if (owned_ && len_ != 0 && expires_at_ms_ == 0) {
    expires_at_ms_ = now_ms + timeout_ms_;
  }

  if (owned_ && len_ != 0 && expires_at_ms_ != 0 && now_ms >= expires_at_ms_) {
    clear_now();
    return;
  }

  // Service pending selection events without blocking.
  while (XPending(dpy_) > 0) {
    XEvent ev;
    XNextEvent(dpy_, &ev);
    handle_event(ev);
  }
}

void secure_clipboard::handle_event(XEvent& ev) {
  if (ev.xany.window != win_) return;
  switch (ev.type) {
    case SelectionRequest:
      handle_selection_request(ev);
      break;
    case SelectionClear:
      handle_selection_clear();
      break;
    default:
      break;
  }
}

void secure_clipboard::handle_selection_clear() {
  // Another owner took over the selection. Our data is no longer the source
  // of truth; wipe it to minimize exposure.
  owned_ = false;
  buffer_.zero();
  len_ = 0;
  expires_at_ms_ = 0;
}

void secure_clipboard::handle_selection_request(XEvent& ev) {
  XSelectionRequestEvent* req = &ev.xselectionrequest;
  if (req->selection != clip_atom_) {
    XSelectionEvent reply{};
    reply.type = SelectionNotify;
    reply.display = req->display;
    reply.requestor = req->requestor;
    reply.selection = req->selection;
    reply.target = req->target;
    reply.property = None;
    reply.time = req->time;
    XSendEvent(dpy_, req->requestor, False, 0,
               reinterpret_cast<XEvent*>(&reply));
    XFlush(dpy_);
    return;
  }

  if (req->target == targets_atom_) {
    respond_with_targets(req->time, req->requestor, req->property);
  } else if (req->target == utf8_atom_ || req->target == string_atom_ ||
             req->target == text_atom_) {
    respond_with_text(req->time, req->requestor, req->property, req->target);
  } else {
    // Unsupported target: refuse.
    XSelectionEvent reply{};
    reply.type = SelectionNotify;
    reply.display = req->display;
    reply.requestor = req->requestor;
    reply.selection = req->selection;
    reply.target = req->target;
    reply.property = None;
    reply.time = req->time;
    XSendEvent(dpy_, req->requestor, False, 0,
               reinterpret_cast<XEvent*>(&reply));
    XFlush(dpy_);
  }
}

void secure_clipboard::respond_with_targets(::Time timestamp, ::Window requestor,
                                            Atom property) {
  Atom targets[kTargetCount] = {
      targets_atom_, utf8_atom_, string_atom_, text_atom_,
      XInternAtom(dpy_, "TIMESTAMP", False)};
  XChangeProperty(dpy_, requestor, property, XA_ATOM, 32, PropModeReplace,
                  reinterpret_cast<unsigned char*>(targets), kTargetCount);

  XSelectionEvent reply{};
  reply.type = SelectionNotify;
  reply.display = dpy_;
  reply.requestor = requestor;
  reply.selection = clip_atom_;
  reply.target = targets_atom_;
  reply.property = property;
  reply.time = timestamp;
  XSendEvent(dpy_, requestor, False, 0, reinterpret_cast<XEvent*>(&reply));
  XFlush(dpy_);
}

void secure_clipboard::respond_with_text(::Time timestamp, ::Window requestor,
                                         Atom property, Atom target) {
  const unsigned char* data =
      (len_ != 0) ? reinterpret_cast<const unsigned char*>(buffer_.data()) : nullptr;
  const std::size_t n = len_;
  XChangeProperty(dpy_, requestor, property, target, 8, PropModeReplace,
                  const_cast<unsigned char*>(data), static_cast<int>(n));

  XSelectionEvent reply{};
  reply.type = SelectionNotify;
  reply.display = dpy_;
  reply.requestor = requestor;
  reply.selection = clip_atom_;
  reply.target = target;
  reply.property = property;
  reply.time = timestamp;
  XSendEvent(dpy_, requestor, False, 0, reinterpret_cast<XEvent*>(&reply));
  XFlush(dpy_);
}

}  // namespace clipboard
