#include "clipboard/secure_clipboard.hpp"

#include <cstring>

#include <sys/select.h>

#include <X11/Xatom.h>

namespace clipboard {

namespace {

constexpr int kTargetCount = 4;

// X11 error handler: a peer may destroy its window just as we write a property
// to it, which Xlib would report as a fatal error and abort the whole process.
// Those failures (BadWindow / BadAtom) are benign for the clipboard path, so
// ignore them instead.
int benign_x_error(Display* /*dpy*/, XErrorEvent* err) {
  (void)err;
  return 0;
}

}  // namespace

bool secure_clipboard::init() {
  if (active_) return true;

  dpy_ = XOpenDisplay(nullptr);
  if (dpy_ == nullptr) {
    active_ = false;
    return false;
  }
  XSetErrorHandler(benign_x_error);

  win_ = XCreateSimpleWindow(dpy_, DefaultRootWindow(dpy_), 0, 0, 1, 1, 0, 0, 0);
  clip_atom_ = XInternAtom(dpy_, "CLIPBOARD", False);
  utf8_atom_ = XInternAtom(dpy_, "UTF8_STRING", False);
  string_atom_ = XInternAtom(dpy_, "STRING", False);
  text_atom_ = XInternAtom(dpy_, "TEXT", False);
  targets_atom_ = XInternAtom(dpy_, "TARGETS", False);
  ts_atom_ = XInternAtom(dpy_, "_SECURE_CLIPBOARD_TS", False);
  incr_atom_ = XInternAtom(dpy_, "INCR", False);
  paste_prop_atom_ = XInternAtom(dpy_, "_SECURE_CLIPBOARD_PASTE", False);
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

bool secure_clipboard::set_text(const char* text, std::size_t len) {
  if (!active_) return false;
  if (len > kMaxClipboardBytes) return false;  // too large for a single property

  // Wipe anything previously held before taking the new content (including any
  // pending paste read buffer).
  buffer_.zero();
  paste_pending_ = false;
  buffer_.resize(len + 1, /*preserve=*/false);
  if (len != 0) std::memcpy(buffer_.data(), text, len);
  buffer_.data()[len] = '\0';
  len_ = len;
  claim_selection();
  return true;
}

bool secure_clipboard::request_paste() {
  if (!active_) return false;
  const ::Window owner = XGetSelectionOwner(dpy_, clip_atom_);
  if (owner == None) return false;
  // Wipe any previous paste result before starting a new read.
  paste_buffer_.zero();
  paste_len_ = 0;
  paste_pending_ = true;
  // Delete any stale paste property so the owner writes fresh.
  XDeleteProperty(dpy_, win_, paste_prop_atom_);
  XConvertSelection(dpy_, clip_atom_, utf8_atom_, paste_prop_atom_, win_,
                    CurrentTime);
  XFlush(dpy_);
  return true;
}

const char* secure_clipboard::paste(std::size_t& out_len) {
  if (paste_pending_) return nullptr;  // not yet arrived; call poll()
  if (paste_len_ == 0) return nullptr;
  out_len = paste_len_;
  return reinterpret_cast<const char*>(paste_buffer_.data());
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
  paste_buffer_.zero();
  paste_len_ = 0;
  paste_pending_ = false;
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
    case SelectionNotify:
      handle_selection_notify(ev);
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
      targets_atom_,
      utf8_atom_,
      string_atom_,
      text_atom_,
  };
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
      (len_ != 0) ? reinterpret_cast<const unsigned char*>(buffer_.data())
                  : nullptr;
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

// ---- Paste (read from external clipboard owners) ----

void secure_clipboard::handle_selection_notify(XEvent& ev) {
  XSelectionEvent* sel = &ev.xselection;
  if (sel->selection != clip_atom_) return;

  if (sel->property == None) {
    // Owner refused the target or selection is empty.
    paste_pending_ = false;
    return;
  }

  // Peek the delivered property type first. If the owner negotiated the INCR
  // protocol (content too large for a single property), this clipboard does not
  // support transferring it; cancel cleanly instead of misreading the announce
  // header as the data.
  Atom actual_type = None;
  int actual_format = 0;
  unsigned long peek_n = 0;
  unsigned long peek_after = 0;
  unsigned char* peek = nullptr;
  XGetWindowProperty(dpy_, sel->requestor, sel->property, 0, 0, False,
                     AnyPropertyType, &actual_type, &actual_format, &peek_n,
                     &peek_after, &peek);
  if (peek != nullptr) XFree(peek);
  if (actual_type == incr_atom_) {
    XDeleteProperty(dpy_, sel->requestor, sel->property);
    XFlush(dpy_);
    paste_pending_ = false;
    return;
  }

  unsigned long total_n = 0;
  unsigned long bytes_after = 0;
  unsigned char* data = nullptr;
  XGetWindowProperty(dpy_, sel->requestor, sel->property, 0, 0x7fffffff,
                     /*delete=*/True, AnyPropertyType, &actual_type,
                     &actual_format, &total_n, &bytes_after, &data);
  paste_buffer_.zero();
  if (data != nullptr) {
    paste_buffer_.resize(total_n + 1);
    if (total_n != 0) std::memcpy(paste_buffer_.data(), data, total_n);
    paste_buffer_.data()[total_n] = '\0';
    paste_len_ = total_n;
    XFree(data);
  }
  paste_pending_ = false;
}

}  // namespace clipboard