# Teach mode: recording a login

## What this is for

Some sites log you in with one form. Others ask for the user name on one page and the password on the next, or run a script that changes the password before it sends it. kharon needs to know which kind a site is before it can handle that login safely. Teach mode is how it learns. You log in by hand once, with a throwaway account, and a small program called `kharon-teach` writes down how the login worked.

This is the first piece of teach mode. It records. kharon cannot yet turn a recording into a login method or replay one; that is later work (#361). For now the recording is a file that a person or a model can read.

## Before you start

Use a throwaway account. Never use a real one. The program reads everything you type in the window it opens, because that is how it learns which field is which. It does not save what you type, but it does read it, and the browser keeps your session until the window closes. If you type a real password by mistake, change that password.

Linux only for now. A Chromium-family browser must be installed: Chromium, Google Chrome, Microsoft Edge or Brave. The program looks for them on your `PATH` in that order, or you can name one with `--browser`.

A browser installed as a snap package cannot use the folder the program makes for its profile, because a snap gets its own private temporary folder. On Ubuntu the default Chromium is a snap. The program skips a snap browser and tries the next one. If a snap is the only browser it finds, it stops and prints "the only browser found is a snap package, which cannot use the recorder's profile folder; install Google Chrome or pass --browser <path>". A browser you name with `--browser` is used as you gave it.

The program always opens a visible window. There is no way to turn that off.

## Recording a login

Give the program the address of the login page:

```text
kharon-teach https://login.example.com/
```

The address must start with `https://`. Plain `http://` is accepted only for `localhost` and other addresses on your own computer. An address that holds a user name or password is refused.

The terminal prints this notice and asks you to agree:

```text
kharon-teach records how a login works so kharon can learn it.
Use a THROWAWAY account. Everything you type in the window that
opens is read by this program. Nothing you type is saved, and
nothing is sent anywhere. The result is one file on this computer.
Type yes to open the browser window and start:
```

Type `yes` and press Enter. Anything else ends the program with "Nothing was recorded." and opens nothing.

A browser window opens on a new, empty profile. Its first page repeats the notice and has one link, "Start recording and open" followed by the site's name. Under the link it says "Open the link in this tab." Recording starts when you click it in that tab. Nothing before that click is recorded. Opening the link in a new tab, or typing an address in another tab, does not start the recording.

The terminal then prints:

```text
Press Enter once you are logged in. Type q to discard.
```

Log in by hand in the window. When you are signed in, go back to the terminal. A recording can end in three ways:

- Press Enter. The recording is saved and marked as a login that worked.
- Type `q` or `quit` (in any letter case) and press Enter. The recording is thrown away and nothing is saved.
- Close the browser window. The recording is saved and marked as a login that was not confirmed. If you close the window before you click the link, nothing is saved.

Any other line you type is not an answer. The program prints "Press Enter to save, or type q to discard." and waits for another line. If the terminal's input ends without a line (it is closed or piped from a file that has run out), the program treats that as neither answer and keeps recording until the window closes.

If the session ends before the recording started, because you pressed Enter before you clicked the link, closed the window first, or opened the link in another tab, nothing is saved. The program prints "Recording never started: the login page was not opened in the first tab. Nothing was saved."

Ctrl-C, a stop request (SIGTERM), closing the terminal window (SIGHUP) or Ctrl-\ (SIGQUIT) ends the program with "Interrupted. Nothing was saved." and a failure exit code. This line and every refusal go to the error output, each starting with "kharon-teach: ".

On every one of these, the program closes the browser and deletes the profile it made. The browser runs in its own process group, so that closing it also closes its helper processes.

If the program itself is killed without a chance to react (SIGKILL, a crash, a power cut), it cannot clean up. Then the browser window stays open, still holding the throwaway session, until you close it. The profile folder is deleted by a later run, and only after that window is closed. A later run deletes a folder only if the program made it: its name is `kharon-teach-` followed by exactly 20 letters and digits, it holds the owner file the program writes with its own process number, that process is no longer running, and no browser is running on it. Any other folder, even one named `kharon-teach-something`, is left alone. When it deletes one, it says "Removed 1 leftover browser profile(s) from an earlier run." before the Enter prompt.

When a recording is saved, the program prints a summary of it and then "Saved:" and the path. The file is named after the site and the time, for example `login.example.com-20261118T061500Z.kharon-recording.json`, and is written in the current directory. Only you can read it (mode `0600`). If a file of that name already exists, the program adds `.1`, then `.2`, up to `.9`, and does not overwrite anything. For a generated name the number goes before `.kharon-recording.json`. For a name you gave with `--out` it goes at the end.

## Options

```text
kharon-teach <LOGIN_URL> [--out <OUT>] [--browser <BROWSER>] [--yes]
kharon-teach show <FILE>
```

| Option | What it does |
|---|---|
| `--out <OUT>` | Where to write the recording. The file must not exist yet, and its folder must exist and be one you can write in. Without it, the file goes in the current directory under the generated name. |
| `--browser <BROWSER>` | The browser program to use, instead of searching `PATH`. The program expects a Chromium-family browser and does not check. |
| `--yes` | Skips the question "Type yes to open the browser window and start". The notice is still printed. |
| `show <FILE>` | Prints what a recording file says, in plain words. It opens no browser and changes nothing. A file larger than 16 MiB, or one that is not a recording this version can read, is refused. |

There is no option to use a browser that is already running, or to pick the profile folder. The program starts its own browser every time.

## What is in the file and what is not

The file describes the structure of the login. It is one JSON document (a plain-text format that programs can read), and it holds nothing you typed. Before the program writes it, everything you typed is reduced to a role (user name or password) and a length. What is kept and what is dropped:

| What the browser showed | What the file keeps |
|---|---|
| What you typed | The role (user name or password) and the length. Every field you typed in counts, not only those two. |
| Request bodies | The shape: the names of the fields, and for each value its kind, its length and, where a typed value was found, its role and how it was encoded. Never the value. A body the program cannot read as the kind its content type says, and a body that would make a shape of more than 2,000 values, is kept as a length only, with the role and encoding of any typed value found in it. A body over 1 MiB is not read at all and is marked `unavailable`: the file says only that its body could not be read. |
| Query strings (`?a=b`) | The names only. |
| Names that do not look like names | A field, part or query name is kept only when it looks like a name: at most 64 characters, all of them letters, digits or one of `_ . : - [ ]`, and not all digits, not a UUID and not 16 or more hex characters. A query piece with no `=` must also be at most 32 characters. Anything else is written `{other}`, because it is more likely a value than a name. A urlencoded body with a piece that has no `=`, or in which most names do not look like names, is not treated as fields at all; it is kept as a length only. |
| Paths (`/a/b`) | The path, with a part replaced by `{id}` when it is all digits, looks like a UUID, is 16 or more hex characters, or contains something you typed. |
| Names that contained something you typed | Replaced by `{typed}`. This covers the names of fields and parts, the labels of a host name and the content type. A typed value found in a name is still recorded as a hit on that field, so the login is read correctly. |
| Web addresses | The scheme is kept only if it is a common one (http, https, ws, wss, data, blob, about, file, chrome, chrome-extension, devtools). Any other is written `{other}`. The content of a `data:` address is never kept. |
| Headers | The content type only. For `Authorization`, only the scheme (for example Basic or Bearer), and only from a known list; any other scheme is written `{other}`. Whether a typed value was in it is recorded. |
| Cookies | Whether a response set one. Nothing else. |
| Responses | For each stored request, the status number (for example 200) and the content type of the reply. |
| Response bodies | Never read. |
| Page text, titles and HTML | Never read. Only the attributes of the fields you used, and of the buttons and links you clicked, are kept: tag, type, `id`, `name`, `autocomplete`, placeholder, aria-label, the form it is in, and a list of ways to find it again. An attribute or way of finding an element that held something you typed is left out. |

Only three kinds of request are stored: pages the main window moved to, requests in which a typed value was found, and any request other than GET to the login site after your first keystroke. All other requests are counted and dropped. A typed value of fewer than six characters can match by chance, so such a match decides nothing when a longer, surer match of the same kind (user name or password) exists in the recording.

The program holds at most 5,000 requests and keeps at most 10,000 steps. Requests past the first 5,000 are counted and not looked at. Steps past 10,000 are not written, but they are counted, and what you typed in them is still found and removed.

The file also records the program version, the browser's name and user agent (the line a browser sends to say what it is), the window size, the start and end times, how the recording ended, and the steps you took: pages visited, fields typed in (by length), clicks, form submissions and Enter presses.

At the end of the file, a `stripped` block counts what was removed: how many requests the browser made and how many were kept, how many typed values, query values and path parts were dropped, how many bodies were reduced to a shape, and how many steps were dropped for being past the limit. The summary prints the same counts, and a line "Not recorded: N step(s) past the recorder's limit." when any steps were dropped.

## Reading the result

The program ends with a summary, and `show` prints the same one later. Each line starts with a label.

Shape of the login ("How the login works"):

| Shape | Meaning |
|---|---|
| `form_post` | One page. The form sends the password to the site as typed or encoded. Encoded means changed back and forth without losing it, for example percent-encoded or base64. |
| `script_post` | One page. The page's script sends the password to the site as typed or encoded. |
| `two_step` | The user name goes first, then the password on a later step. The summary says how the password was sent: by a form, by a script, or changed by the page first. |
| `transformed` | The page changes the password before sending it, so no request holds it as typed. If the change was a known digest, the summary names it. A digest is a fixed-length scramble of the password that cannot be turned back (md5, sha1, sha256 or sha512). |
| `unrecognized` | None of the above. This also covers a recording in which no password field was used, one in which the password was sent in a way the program does not know, one in which request bodies were unavailable and the password was found nowhere, and one with a flag below that needs a person to look. |

Strongest protection ("Strongest protection"), the best that kharon could do for this login:

| Value | Meaning |
|---|---|
| `milliseconds` | kharon could fill and submit in one step, so the password is in the page for milliseconds. |
| `agent_continues` | The agent has to continue after the fill. This is the case for two-step logins, logins with a captcha or a one-time-code step, and one-page logins where the password field was not in a form and no Enter key and no click on a button followed it. |
| `needs_person` | A person has to look at the recording. This includes a two-step login whose password step is changed by the page, unless the change is a digest the program can name. With a named digest, the result is `agent_continues` and a note names the digest. |

"Network swap" says whether the password was found, as typed or encoded but not hashed, in exactly one stored request. Such a login might let kharon put the password in as the request leaves the browser, so the page never holds it. kharon cannot do this yet. The line records which logins might allow it.

Flags, each printed as "Flag:" with a sentence:

| Flag | Meaning |
|---|---|
| `captcha` | A captcha was on the page. The program knows five captcha hosts, plus Google's. |
| `otp_step` | There was a field for a one-time code after the password. |
| `cross_site` | The browser moved to another web site before the password was sent, as single sign-on does. Only a move to another web site (an `http` or `https` page of another registrable domain) counts; a browser error page does not. A move after the password was sent is not a flag. A login that lands on another site afterwards is still read normally, and the summary adds the note "After the login the browser went on to another site." |
| `popup` | The login opened another window. |
| `framed_login` | A login field was inside a frame from another web address. |
| `shadow_dom` | A login field was inside a shadow root, a part of the page that hides its fields from ordinary lookups. |
| `multiple_passwords` | The page had two password fields with different values, as a sign-up or change-password form does. |
| `body_unavailable` | The browser would not hand over the body of some request, so the shape may be incomplete. |

`cross_site`, `popup`, `framed_login` and `multiple_passwords` make the shape `unrecognized`. The summary may also print "Note:" lines that say why in plain words.

A "Caution" line appears when the page's own scripts could see and fake what the program reports. Trust such a recording less.

## Sending a recording to someone

A recording is an ordinary file. The program never sends it anywhere. If you want someone to read it, you copy it to them yourself.

Before you do, run `kharon-teach show <FILE>` and read what it says. The `stripped` block at the end of the file lets the reader check what was removed: the number of typed values, query values and path parts dropped, and how many requests were kept out of how many seen. The file still names the site you recorded and the structure of its login, so send it only to someone who may know which site that is.

## What it cannot do

- It records in a visible desktop browser. The agent's browser is usually headless, and a site may lay itself out differently there. The file records the window size and the user agent so a mismatch can be seen later.
- A site with bot detection may treat a fresh profile with a debugging port differently from your everyday browser.
- If you type a real password despite the notice, the program still writes it nowhere, but it read it, and the browser held it until the profile was deleted.
- If the program is killed without a chance to react (SIGKILL, a crash, a power cut), the browser window stays open with the throwaway session in it. Its profile is deleted by a later run, only after that window is closed.
- While a recording runs, the browser's debugging port listens on 127.0.0.1. Any program on the computer, including another user's program on a shared machine, can connect to it and read what is typed. Record only on a computer you do not share.
- A browser installed as a snap package is skipped, because it cannot use the profile folder (see "Before you start"). This has not been tried on an Ubuntu machine yet. If the program fails to start the browser there, pass `--browser` with Google Chrome or a Chromium that is not a snap.
- It does not detect passkey logins.
- It does not follow web workers or service workers.
- It finds a typed value in a request only in forms it knows: as typed, percent-encoded, escaped for JSON, base64, base64url and hex, and for the password the md5, sha1, sha256 and sha512 digests in hex or base64. A site that lowercases or re-encodes a typed value before sending it may not be recognised as the user name.
- A typed value that a site sends as a JSON number is looked for as its text. If the site writes the number differently from how it was typed, it is not found.
- A typed value shorter than six characters, such as a PIN, is searched for, but a match is marked low confidence, because it may be chance. In text the program keeps (paths, query names, hosts) it is removed only where it stands as a whole word, so that it does not damage ordinary words. In requests its matches are weak hints, and they can point at the wrong request when the same few characters appear by chance in another one.
- If you mistype the password and the page reloads before you get it right, the recording reads as a sign-up form (two password values) and needs a person. Start the recording again instead.
- Logins the page's script cannot see are not recognised: the browser's own Basic or Digest login dialog, passkeys, and fields drawn on a canvas or typed into a `contenteditable` element.
- A captcha script that only loads on the page (reCAPTCHA v3, Cloudflare Turnstile) sets the `captcha` flag and lowers the result to `agent_continues`, even when no challenge was shown.
- A password sent over a WebSocket, through a service worker or from another tab is not found, and neither is a change outside the encodings and digests listed above. Such a login comes out as `transformed` or `unrecognized`.
- Opening the link on the notice page in a new tab, or typing another address, means the recording never starts. The page says to open the link in the same tab.
- Once 32 MiB of request bodies are held, later bodies are recorded as unavailable.
- A `transformed` login with no named digest is mostly a site that encrypts the password in the page with a key the site supplies, as banks often do. It is an expected result and is marked `needs_person`.
- A recording made with the listener in the page's own script world, not the isolated one, is marked as such and is less trustworthy.
- Turning a recording into a login method is not built yet.
