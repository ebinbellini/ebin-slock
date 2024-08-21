// See LICENSE file for license details.
#define _XOPEN_SOURCE 500
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <X11/keysym.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xresource.h>
#include <X11/Xutil.h>
#include <time.h>
#include <crypt.h>

#if HAVE_BSD_AUTH
#include <login_cap.h>
#include <bsd_auth.h>
#endif

#include "drw/drw.h"
#include "drw/util.h"

#define CMD_LENGTH 500
#define LENGTH(X)  (sizeof X / sizeof X[0])

#define POWEROFF 0
#define USBOFF 0
#define STRICT_USBOFF 0
#define TWILIO_SEND 0
#define WEBCAM_SHOT 1
#define IMGUR_UPLOAD 0
#define PLAY_AUDIO 1

char *g_pw = NULL;
int lock_tries = 0;

typedef struct {
    char* name;
    char** dst;
} ColorPreference;

static Drw **locks;
static Fnt *font;
static int nscreens;
static Bool running = True;

#ifdef __linux__
#include <fcntl.h>

static void
dontkillme(void) {
  errno = 0;
  int fd = open("/proc/self/oom_score_adj", O_WRONLY);

  if (fd < 0 && errno == ENOENT)
    return;

  if (fd < 0)
    goto error;

  if (write(fd, "-1000\n", 6) != 6) {
    close(fd);
    goto error;
  }

  if (close(fd) != 0)
    goto error;

  return;

error:
  fprintf(stderr, "cannot disable the OOM killer for this process\n");
  fprintf(stderr, "trying with sudo...\n");

  pid_t pid = getpid();

  char cmd[CMD_LENGTH];

  int r = snprintf(
    cmd,
    CMD_LENGTH,
    "echo -1000 | sudo -n tee /proc/%u/oom_score_adj > /dev/null 2>& 1",
    (unsigned int)pid
  );

  if (r >= 0 && r < CMD_LENGTH)
    system(cmd);
}
#endif

#ifndef HAVE_BSD_AUTH

static const char *
getpw(void) {
  const char *rval;
  struct passwd *pw;

  if (g_pw)
    return g_pw;

  errno = 0;
  pw = getpwuid(getuid());

  if (!pw) {
    if (errno)
      die("slock: getpwuid: %s\n", strerror(errno));
    else
      die("slock: cannot retrieve password entry\n");
  }

  endpwent();
  rval = pw->pw_passwd;

#if HAVE_SHADOW_H
  if (rval[0] == 'x' && rval[1] == '\0') {
    struct spwd *sp;
    sp = getspnam(getenv("USER"));
    if (!sp)
      die("slock: cannot retrieve shadow entry\n");
    endspent();
    rval = sp->sp_pwdp;
  }
#endif

  // drop privileges
  if (geteuid() == 0) {
    if (!(getegid() != pw->pw_gid && setgid(pw->pw_gid) < 0)) {
      if (setuid(pw->pw_uid) < 0)
        die("slock: cannot drop privileges\n");
    }
  }

  return rval;
}
#endif

static char *
read_file(char *name) {
  FILE *f = fopen(name, "r");

  if (f == NULL)
    goto error;

  struct stat s;

  if (stat(name, &s) == -1) {
    fclose(f);
    goto error;
  }

  char *buf = malloc(s.st_size);

  if (buf == NULL) {
    fclose(f);
    goto error;
  }

  fread(buf, 1, s.st_size, f);
  fclose(f);

  char *c = buf;
  while (*c) {
    if (*c == '\r' || *c == '\n') {
      *c = '\0';
      break;
    }
    c++;
  }

  return buf;

error:
    fprintf(stderr, "Could not open: %s.\n", name);
    return NULL;
}

// Disable alt+sysrq and crtl+alt+backspace - keeps the
// attacker from alt+sysrq+k'ing our process
static void
disable_kill(void) {
#if POWEROFF
  // Needs sudo privileges - alter your /etc/sudoers file:
  // [username] [hostname] =NOPASSWD: /usr/bin/tee /proc/sys/kernel/sysrq
  // Needs sudo privileges - alter your /etc/sudoers file:
  // [username] [hostname] =NOPASSWD:
  // /usr/bin/tee /proc/sys/kernel/sysrq,/usr/bin/tee /proc/sysrq-trigger
  // system("echo 1 | sudo -n tee /proc/sys/kernel/sysrq > /dev/null");
  // system("echo o | sudo -n tee /proc/sysrq-trigger > /dev/null");
  system("echo 0 | sudo -n tee /proc/sys/kernel/sysrq > /dev/null 2>& 1 &");
  // Disable ctrl+alt+backspace
  system("setxkbmap -option &");
#else
  return;
#endif
}

// Poweroff if we're in danger.
static void
poweroff(void) {
#if POWEROFF
  // Needs sudo privileges - alter your /etc/sudoers file:
  // systemd: [username] [hostname] =NOPASSWD: /usr/bin/systemctl poweroff
  // sysvinit: [username] [hostname] =NOPASSWD: /usr/bin/shutdown -h now
  system("sudo -n systemctl poweroff 2> /dev/null");
  system("sudo -n shutdown -h now 2> /dev/null");
#else
  return;
#endif
}

// Turn USB off on lock.
static void
usboff(void) {
#if USBOFF
  // Needs sudo privileges - alter your /etc/sudoers file:
  // [username] [hostname] =NOPASSWD:
  // /sbin/sysctl kernel.grsecurity.deny_new_usb=1
  system("sudo -n sysctl kernel.grsecurity.deny_new_usb=1 2> /dev/null");
#if STRICT_USBOFF
  system("sudo -n sysctl kernel.grsecurity.grsec_lock=1 2> /dev/null");
#endif
#else
  return;
#endif
}

// Turn on USB when the correct password is entered.
static void
usbon(void) {
#if USBOFF
  // Needs sudo privileges - alter your /etc/sudoers file:
  // [username] [hostname] =NOPASSWD:
  // /sbin/sysctl kernel.grsecurity.deny_new_usb=0
  system("sudo -n sysctl kernel.grsecurity.deny_new_usb=0 2> /dev/null");
#else
  return;
#endif
}

// Take a screenshot of whoever is at the keyboard.
static int
webcam_shot(int async) {
#if WEBCAM_SHOT
  char cmd[CMD_LENGTH];

  time_t tt = time(NULL);
  struct tm t = *localtime(&tt);

  int r = snprintf(
    cmd,
    CMD_LENGTH,
    "ffmpeg -y -loglevel quiet -f video4linux2 -i /dev/video0"
    " -frames:v 1 -f image2 %s/Images/loginattempts/%d-%02d-%02d_%02d:%02d:%02d.jpg%s",
    getenv("HOME"),
    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
    async ? " &" : ""
  );

  if (r < 0 || r >= CMD_LENGTH)
    return 0;

  system(cmd);

  return 1;
#else
  return 0;
#endif
}

// Send an SMS via twilio.
static int
twilio_send(const char *msg, char *link, int async) {
#if TWILIO_SEND
  char cmd[CMD_LENGTH];

  // Send the SMS/MMS via Twilio
  int r = snprintf(
    cmd,
    CMD_LENGTH,
    "curl -s -A '' -X POST https://api.twilio.com/2010-04-01/Accounts/"
    TWILIO_ACCOUNT "/SMS/Messages.json"
    " -u " TWILIO_AUTH
    " --data-urlencode 'From=" TWILIO_FROM "'"
    " --data-urlencode 'To=" TWILIO_TO "'"
    " --data-urlencode 'Body=%s'"
    " --data-urlencode 'MediaUrl=%s' > /dev/null"
    "%s",
    msg,
    link != NULL ? link : "",
    async ? " &" : ""
  );

  if (r < 0 || r >= CMD_LENGTH)
    return 0;

  system(cmd);

  return 1;
#else
  return 0;
#endif
}

// Upload image for MMS.
static int
imgur_upload(char **link, char **hash) {
  *link = NULL;
  *hash = NULL;

#if IMGUR_UPLOAD
  const char *HOME = getenv("HOME");
  char cmd[CMD_LENGTH];
  int r;

  // Upload the imgur image:
  r = snprintf(
    cmd,
    CMD_LENGTH,
    "curl -s -A '' -X POST"
    " -H 'Authorization: Client-ID " IMGUR_CLIENT "'"
    " -F 'image=@%s/slock.jpg'"
    " 'https://api.imgur.com/3/image' > %s/slock_imgur.curl",
    HOME,
    HOME
  );

  if (r < 0 || r >= CMD_LENGTH)
    goto cleanup;

  system(cmd);

  // Get the link:
  r = snprintf(
    cmd,
    CMD_LENGTH,
    "cat %s/slock_imgur.curl"
    " | grep -o '\"link\":\"[^\"]\\+'"
    " | sed 's/\\\\//g'"
    " | grep -o '[^\"]\\+$'"
    " > %s/slock_imgur.link",
    HOME,
    HOME
  );

  if (r < 0 || r >= CMD_LENGTH)
    goto cleanup;

  system(cmd);

  // Get the hash:
  r = snprintf(
    cmd,
    CMD_LENGTH,
    "cat %s/slock_imgur.curl"
    " | grep -o '\"deletehash\":\"[^\"]\\+'"
    " | grep -o '[^\"]\\+$'"
    " > %s/slock_imgur.hash",
    HOME,
    HOME
  );

  if (r < 0 || r >= CMD_LENGTH)
    goto cleanup;

  system(cmd);

  r = snprintf(cmd, CMD_LENGTH, "%s/slock_imgur.link", HOME);

  if (r < 0 || r >= CMD_LENGTH)
    goto cleanup;

  *link = read_file(cmd);

  r = snprintf(cmd, CMD_LENGTH, "%s/slock_imgur.hash", HOME);

  if (r < 0 || r >= CMD_LENGTH)
    goto cleanup;

  *hash = read_file(cmd);

cleanup:
  r = snprintf(cmd, CMD_LENGTH, "%s/slock_imgur.curl", HOME);

  if (r >= 0 && r < CMD_LENGTH)
    unlink(cmd);

  r = snprintf(cmd, CMD_LENGTH, "%s/slock_imgur.link", HOME);

  if (r >= 0 && r < CMD_LENGTH)
    unlink(cmd);

  r = snprintf(cmd, CMD_LENGTH, "%s/slock_imgur.hash", HOME);

  if (r >= 0 && r < CMD_LENGTH)
    unlink(cmd);

  if (*link == NULL || *hash == NULL) {
    if (*link != NULL)
      free(*link);
    if (*hash != NULL)
      free(*hash);
    return 0;
  }

  return 1;
#else
  return 0;
#endif
}

// Delete image once MMS is sent.
static int
imgur_delete(char *hash) {
#if IMGUR_UPLOAD
  char cmd[CMD_LENGTH];

  // Delete the imgur image:
  int r = snprintf(
    cmd,
    CMD_LENGTH,
    "curl -s -A '' -X DELETE"
    " -H 'Authorization: Client-ID " IMGUR_CLIENT "'"
    " 'https://api.imgur.com/3/image/%s'",
    hash
  );

  if (r < 0 || r >= CMD_LENGTH)
    return 0;

  system(cmd);

  return 1;
#else
  return 0;
#endif
}

static int
play_beep(int async) {
#if PLAY_AUDIO
  char cmd[CMD_LENGTH];

  int r = snprintf(
    cmd,
    CMD_LENGTH,
    "aplay %s/slock/beep.wav 2> /dev/null%s",
    getenv("HOME"),
    async ? " &" : ""
  );

  if (r >= 0 && r < CMD_LENGTH)
    system(cmd);

  return 1;
#else
  return 0;
#endif
}

static int
play_alarm(int async) {
#if PLAY_AUDIO
  char cmd[CMD_LENGTH];

  int r = snprintf(
    cmd,
    CMD_LENGTH,
    "aplay %s/slock/police.wav 2> /dev/null%s",
    getenv("HOME"),
    async ? " &" : ""
  );

  if (r >= 0 && r < CMD_LENGTH)
    system(cmd);

  return 1;
#else
  return 0;
#endif
}

static void
draw(Drw *drw, int pwdlen)
{
  XClearWindow(drw->dpy, drw->root);

  const int w = drw->w;
  const int h = drw->h;

  char buf[255] = "";
  int i;
  for (i = 0; i < sizeof (buf) - 2 && i < pwdlen; i++)
    buf[i] = '*';
  buf[i+1] = '\0';

  // Draw lock icon
  const int lockwidth = 200;
  const int lockheight = lockwidth * 3 / 4;
  // Lock contour
  drw_rect(drw, w/2 - lockwidth/2, h/2 - lockheight / 2, lockwidth, lockheight, 0, 1);
  // Keyhole square
  drw_rect(drw, w/2-lockwidth/8.4, h/2+lockwidth/32, lockwidth/4.2, lockwidth/4, 0, 1);
  drw_rect(drw, w/2-lockwidth/8+4, h/2+lockwidth/32-2, lockwidth/4 - 8, 8, 1, 0);
  // Lock bar arc
	XSetForeground(drw->dpy, drw->gc, drw->scheme[ColBg].pixel);
  XDrawArc(drw->dpy, drw->drawable, drw->gc, w/2-lockwidth/3, h/2-lockheight/2 - lockwidth/3, lockwidth/1.5, lockwidth/1.5, -0, 180 * 64);
  // Keyhole arc
  XDrawArc(drw->dpy, drw->drawable, drw->gc, w/2-lockwidth/6, h/2 - lockwidth/4, lockwidth/3, lockwidth/3, -45 * 64, 45 * 6 * 64);

  // Draw *******
  unsigned int text_w = drw_fontset_getwidth(drw, buf);
  drw_rect(drw, w/2-500, h/2 + lockwidth * 0.8, 1000, 50, 1, 0);
  drw_text(drw, w/2-text_w/2, h/2 + lockwidth * 0.8, text_w, 50, 0, buf, 1);

  drw_map(drw, drw->root, 0, 0, w, h);
}

static void
#ifdef HAVE_BSD_AUTH
readpw(Display *dpy)
#else
readpw(Display *dpy, const char *pws)
#endif
{
  char buf[32], passwd[256];
  int num, screen;
  unsigned int len = 0;
  KeySym ksym;
  XEvent ev;

  running = True;

  for (screen = 0; screen < nscreens; screen++) {
    // Draw empty screen
    draw(locks[screen], 0);
  }

  // As "slock" stands for "Simple X display locker", the DPMS settings
  // had been removed and you can set it with "xset" or some other
  // utility. This way the user can easily set a customized DPMS
  // timeout.
  while (running && !XNextEvent(dpy, &ev)) {
    if (ev.type != KeyPress) {
      for (screen = 0; screen < nscreens; screen++)
        XRaiseWindow(dpy, locks[screen]->root);
      continue;
    }

    buf[0] = 0;

    num = XLookupString(&ev.xkey, buf, sizeof(buf), &ksym, 0);

    if (IsKeypadKey(ksym)) {
      if (ksym == XK_KP_Enter)
        ksym = XK_Return;
      else if (ksym >= XK_KP_0 && ksym <= XK_KP_9)
        ksym = (ksym - XK_KP_0) + XK_0;
    }

    if (IsFunctionKey(ksym)
        || IsKeypadKey(ksym)
        || IsMiscFunctionKey(ksym)
        || IsPFKey(ksym)
        || IsPrivateKeypadKey(ksym)
        || IsModifierKey(ksym)) {
      continue;
    }

    switch(ksym) {
      case XK_Return: {
        passwd[len] = 0;

        if (g_pw) {
          running = strcmp(passwd, g_pw) != 0;
        } else {
#ifdef HAVE_BSD_AUTH
          running = !auth_userokay(getlogin(), NULL, "auth-xlock", passwd);
#else
          running = strcmp(crypt(passwd, pws), pws) != 0;
#endif
        }

        if (running) {
          // Take a webcam shot of whoever is tampering with our machine:
          webcam_shot(0);
          XBell(dpy, 100);
          lock_tries++;

          // Poweroff if there are more than 5 bad attempts.
          if (lock_tries > 5) {
            // Disable alt+sysrq and ctrl+alt+backspace
            disable_kill();

            // Upload the image:
            char *link, *hash;
            int success = imgur_upload(&link, &hash);

            // Send an SMS/MMS via twilio.
            twilio_send("Bad screenlock password.", link, 0);

            // Success. Cleanup.
            if (success) {
              // Delete the image from imgur.
              imgur_delete(hash);

              free(link);
              free(hash);
            }

            // Immediately poweroff:
            poweroff();

            // If we failed, loop forever.
            for (;;)
              sleep(1);
          }

          // Play a siren if there are more than 2 bad
          // passwords, a beep if a correct password.
          if (lock_tries > 2) {
            play_alarm(0);
          } else {
            play_beep(0);
          }
        }

        len = 0;

        break;
      }
      case XK_Escape: {
        len = 0;
        break;
      }
      case XK_Delete:
      case XK_BackSpace: {
        if (len)
          len -= 1;
        break;
      }
      case XK_Alt_L:
      case XK_Alt_R:
      case XK_Control_L:
      case XK_Control_R:
      case XK_Meta_L:
      case XK_Meta_R:
      case XK_Super_L:
      case XK_Super_R:
      case XK_F1:
      case XK_F2:
      case XK_F3:
      case XK_F4:
      case XK_F5:
      case XK_F6:
      case XK_F7:
      case XK_F8:
      case XK_F9:
      case XK_F10:
      case XK_F11:
      case XK_F12:
      case XK_F13: {
        // Disable alt+sysrq and ctrl+alt+backspace.
        disable_kill();

        // Take a webcam shot of whoever
        // is tampering with our machine.
        webcam_shot(0);

        // Upload our image:
        char *link, *hash;
        int success = imgur_upload(&link, &hash);

        // Send an SMS/MMS via twilio.
        twilio_send("Bad screenlock key.", link, 0);

        // Success. Cleanup.
        if (success) {
          // Delete the image from imgur.
          imgur_delete(hash);

          free(link);
          free(hash);
        }

        // Immediately poweroff:
        poweroff();

        // If we failed, loop forever.
        for (;;)
          sleep(1);

        break;
      }
      default: {
        if (num && !iscntrl((int)buf[0]) && (len + num < sizeof(passwd))) {
          memcpy(passwd + len, buf, num);
          len += num;
        }
        break;
      }
    }

    for (screen = 0; screen < nscreens; screen++) {
      draw(locks[screen], len);
    }
  }
}

static void
unlockscreen(Display *dpy, Drw *drw) {
  usbon();

  if (dpy == NULL || drw == NULL)
    return;

  XUngrabPointer(dpy, CurrentTime);

  XDestroyWindow(dpy, drw->root);

  drw_free(drw);
}

static Drw *
lockscreen(Display *dpy, int screen) {
  unsigned int len;
  XSetWindowAttributes wa;

  if (dpy == NULL || screen < 0)
    return NULL;

  // init
  wa.override_redirect = 1;
  wa.background_pixel = BlackPixel(dpy, screen);
  wa.border_pixel = 0;
  int field = CWOverrideRedirect | CWBackPixel | CWBorderPixel;

  Window root = DefaultRootWindow(dpy);
  Window win = win = XCreateWindow(
    dpy,
    root,
    0,
    0,
    DisplayWidth(dpy, screen),
    DisplayHeight(dpy, screen),
    0,
    DefaultDepth(dpy, screen),
    CopyFromParent,
    DefaultVisual(dpy, screen),
    field,
    &wa
  );

  // Init suckless drw library
  int w = DisplayWidth(dpy, screen);
  int h = DisplayHeight(dpy, screen);
  Drw *drw = drw_create(dpy, screen, win, w, h);

  XSetLineAttributes(dpy, drw->gc, 5, LineSolid, CapButt, JoinMiter);

  static char* col_background = "#000000";
  //static char* col_foreground = "#f8a235";
  static char* col_foreground = "#ffffff";

  // Try to get colors from .Xresources
	XrmInitialize();
  char *resource_manager = XResourceManagerString(drw->dpy);
	if (resource_manager != NULL) {
    XrmDatabase db = XrmGetStringDatabase(resource_manager);

    ColorPreference c_prefs[] = {
      { "foreground", &col_background },
      { "color11", &col_foreground },
    };

    ColorPreference *c;
    for (c = c_prefs; c < c_prefs + LENGTH(c_prefs); c++) {
      char *type;
      XrmValue value;
      char fullname[256];
      char fullclass[256];
      snprintf(fullname, sizeof(fullname), "%s.%s", "slock", c->name);
      snprintf(fullclass, sizeof(fullclass), "%s.%s", "Slock", c->name);
      fullname[sizeof(fullname) - 1] = fullclass[sizeof(fullclass) - 1] = '\0';
      XrmGetResource(db, fullname, fullclass, &type, &value);
      if (value.addr != NULL && !strncmp("String", type, 64)) {
        *c->dst = value.addr;
      }
    }
  }

  char * palette[] = { col_background, col_foreground };
  drw->scheme = drw_scm_create(drw, (const char **)palette, 2);
  drw_setscheme(drw, drw->scheme);

  unsigned long black, white;
  black = BlackPixel(dpy, screen);
  white = WhitePixel(dpy, screen);
  XSetBackground(drw->dpy, drw->gc, black);
  XSetForeground(drw->dpy, drw->gc, white);

  XSelectInput(dpy, win, ExposureMask|ButtonPressMask|KeyPressMask);
  XClearWindow(drw->dpy, drw->root);
  XMapRaised(drw->dpy, drw->root);

  static const char *fontlist[] = { "Atari ST 8x16 System Font:pixelsize=40" };
  font = drw_fontset_create(drw, fontlist, LENGTH(fontlist));

  field = CWOverrideRedirect | CWBackPixel;
  Atom name_atom = XA_WM_NAME;
  XTextProperty name_prop = { "slock", name_atom, 8, 5 };
  XSetWMName(dpy, drw->root, &name_prop);

  XClassHint *hint = XAllocClassHint();
  if (hint) {
    hint->res_name = "slock";
    hint->res_class = "slock";
    XSetClassHint(dpy, drw->root, hint);
    XFree(hint);
  }

  // Hide cursor
  Cursor invisible;
  XColor color, dummy;
  char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
  int cmap = DefaultColormap(dpy, drw->screen);
  XAllocNamedColor(dpy, cmap, "black", &color, &dummy);
  Pixmap pmap = XCreateBitmapFromData(dpy, drw->root, curs, 8, 8);
  invisible = XCreatePixmapCursor(
    dpy, pmap, pmap, &color, &color, 0, 0);
  XDefineCursor(dpy, drw->root, invisible);

  XMapRaised(dpy, drw->root);
  XFreeColors(dpy, DefaultColormap(dpy, drw->screen), &color.pixel, 1, 0);
  XFreeColors(dpy, DefaultColormap(dpy, drw->screen), &dummy.pixel, 1, 0);

  for (len = 1000; len > 0; len--) {
    int field = ButtonPressMask | ButtonReleaseMask | PointerMotionMask;

    int grab = XGrabPointer(
      dpy,
      drw->root,
      False,
      field,
      GrabModeAsync,
      GrabModeAsync,
      None,
      invisible,
      CurrentTime
    );

    if (grab == GrabSuccess)
      break;

    usleep(1000);
  }

  if (running && (len > 0)) {
    for (len = 1000; len; len--) {
      int grab = XGrabKeyboard(
        dpy,
        drw->root,
        True,
        GrabModeAsync,
        GrabModeAsync,
        CurrentTime
      );

      if (grab == GrabSuccess)
        break;

      usleep(1000);
    }
  }

  running &= (len > 0);

  if (!running) {
    unlockscreen(dpy, drw);
    drw = NULL;
  } else {
    XSelectInput(dpy, drw->root, SubstructureNotifyMask);
    usboff();
  }

  return drw;
}

static void
usage(void) {
  fprintf(stderr, "usage: slock [-v]\n");
  exit(EXIT_FAILURE);
}

static char *
read_pw_file(void) {
  char name[256];

  int r = snprintf(
    name,
    sizeof(name),
    "%s/.slock_passwd",
    getenv("HOME")
  );

  if (r < 0 || r >= sizeof(name))
    return NULL;

  return read_file(name);
}

int
main(int argc, char **argv) {
#ifndef HAVE_BSD_AUTH
  const char *pws;
#endif
  Display *dpy;
  int screen;

#ifdef SLOCK_QUIET
  freopen("/dev/null", "a", stdout);
  freopen("/dev/null", "a", stderr);
#endif

  g_pw = read_pw_file();

  if ((argc >= 2) && strcmp(argv[1], "-v") == 0) {
    die("slock-%s, © 2006-2012 Anselm R Garbe\n", VERSION);
  } else if (argc != 1) {
    usage();
  }

#ifdef __linux__
  dontkillme();
#endif

  if (!g_pw && !getpwuid(getuid()))
    die("slock: no passwd entry for you\n");

#ifndef HAVE_BSD_AUTH
  pws = getpw();
#endif

  dpy = XOpenDisplay(0);
  if (!dpy)
    die("slock: cannot open display\n");

  // Get the number of screens in display "dpy" and blank them all.
  nscreens = ScreenCount(dpy);

  errno = 0;
  locks = malloc(sizeof(Drw *) * nscreens);

  if (locks == NULL)
    die("slock: malloc: %s\n", strerror(errno));

  int nlocks = 0;

  for (screen = 0; screen < nscreens; screen++) {
    locks[screen] = lockscreen(dpy, screen);
    if (locks[screen] != NULL)
      nlocks++;
  }

  XSync(dpy, False);

  // Did we actually manage to lock something?
  if (nlocks == 0) { // nothing to protect
    free(locks);
    XCloseDisplay(dpy);
    return 1;
  }

  // Everything is now blank. Now wait for the correct password.
#ifdef HAVE_BSD_AUTH
  readpw(dpy);
#else
  readpw(dpy, pws);
#endif

  // Password ok, unlock everything and quit.
  for (screen = 0; screen < nscreens; screen++)
    unlockscreen(dpy, locks[screen]);

  free(locks);
  XCloseDisplay(dpy);

  return 0;
}
