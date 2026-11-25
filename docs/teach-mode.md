# Teach mode: recording a login

## What this is for

Some sites log you in with one form. Others ask for the user name on one page and the password on the next, or run a script that changes the password before it sends it. kharon needs to know which kind a site is before it can handle that login safely. Teach mode is how it learns. You log in by hand once, with a throwaway account, and a small program called `kharon-teach` writes down how the login worked.

Teach mode has three steps. First, `kharon-teach` records a login done by hand. Second, `kharon-teach method` turns the recording into a **login method**, a small file that names the fields and the submit of one site's login and holds no typed value. Third, the broker's owner imports the method with `kharon teach import`. From then on, when an agent asks kharon to fill a user name or a password on that site, the broker fills it by the method. This page covers the recording first, then the method, the import, what a fill does on a taught site, and how to write a method by hand. "What is not built yet" lists what is left of #361.

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
kharon-teach method <RECORDING> [--out <OUT>] [--unconfirmed] [--success <path-changed|password-field-gone|none>]
```

| Option | What it does |
|---|---|
| `--out <OUT>` | Where to write the recording. The file must not exist yet, and its folder must exist and be one you can write in. Without it, the file goes in the current directory under the generated name. |
| `--browser <BROWSER>` | The browser program to use, instead of searching `PATH`. The program expects a Chromium-family browser and does not check. |
| `--yes` | Skips the question "Type yes to open the browser window and start". The notice is still printed. |
| `show <FILE>` | Prints what a recording file, or a login method file, says, in plain words. It opens no browser and changes nothing. A file larger than 16 MiB, or one that is not a recording or a method this version can read, is refused. |
| `method <RECORDING>` | Converts a recording into a login method (see the next section). It opens no browser. |

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
| `cross_site` | The browser moved to another web site before the password was last sent, as single sign-on does. Only a move to another web site (an `http` or `https` page of another registrable domain) counts; a browser error page does not. A move after the last request that carried the password is not a flag. A login that lands on another site afterwards is still read normally, and the summary adds the note "After the login the browser went on to another site." |
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

## Turning a recording into a login method

```text
kharon-teach method login.example.com-20261118T061500Z.kharon-recording.json
```

The program reads the recording and writes `<registrable domain>.kharon-method.json` in the current directory, for example `example.com.kharon-method.json`. The file has mode `0600`, and the program does not overwrite a file that exists. `--out <OUT>` names the file instead; it must not exist yet. The program prints "Saved:" and the path, then the same plain-words summary that `kharon-teach show` prints for a method file. Read it before you import it. Nothing here opens a browser or touches the network.

It converts a recording whose shape is `form_post`, `script_post` or `two_step`, or `transformed` when the summary names the digest. It refuses, and prints why, in these cases:

- The shape is `unrecognized`, the strongest protection is `needs_person`, or the shape is `transformed` with no named digest. A person has to write such a method by hand (see "Writing a method by hand").
- A user name or password field sat in a shadow root. A fill cannot reach into one, and a hand-written method cannot either.
- A part of the login has no submit after its last field.
- The recording was marked "not confirmed" (you closed the window instead of pressing Enter). Pass `--unconfirmed` to convert it anyway.

What the file keeps: for each step of the login, the role (user name or password), a list of ways to find the element again, and what the element must look like (its tag, `type`, `id`, `name` and `autocomplete`), plus how the step was submitted (the form, Enter, or a click on one element). It also keeps the site's registrable domain and the login page's origin and path, the shape, the rung (below), how kharon will tell that the login worked, and where the method came from: the SHA-256 of the recording file, the recorder's version, the browser's product string, whether the recorder's listener ran in the isolated or the page's own script world, and the recording's strongest protection. It holds no typed value, no value length, no query key, no request, no placeholder or label text and no page text.

The method's rung is the recording's "Strongest protection" (see "Reading the result"). `milliseconds` means a fill submits the login in the same step as the fill, so the password is in the page for milliseconds. `agent_continues` means the agent has to continue after the fill. A two-step login is always `agent_continues`, and each of its two parts is one fill by the agent.

How kharon tells that the login worked: if the recording ended on another path than where the last part of the login starts (the login page, or for a two-step login the password page), the login worked when the page's path becomes that path (`path_changed_to`). If it ended on the same path, kharon does not check (`none`). `--success` overrides this with `path-changed`, `password-field-gone` (the password field is gone from the page, for a login script that removes its form) or `none`. The check is read once, after the fill, and goes only to the registry entry. The fill's reply is still `filled`.

## Importing a method into the broker

Only the broker's owner can add a method. The commands talk to the daemon over its owner socket, which only the owner's own user can open, so an agent has no route to them. They work while the vault is locked. Each takes `--socket <PATH>` if the socket is not `/data/owner.sock`.

| Command | What it does |
|---|---|
| `kharon teach import <FILE> [--replace] [--accept-main-world]` | Prints a summary of the method, then adds it for its site. |
| `kharon teach list` | One line per site: the domain, the rung, the shape, whether the method was converted or hand-written, whether it is stale, and the result and time of the last fill by the method. |
| `kharon teach show <DOMAIN>` | The same line, then every step with its number, counted from 0 across both parts of a two-step login. Selectors you have added show as `[override]`. |
| `kharon teach override <DOMAIN> <STEP> <SELECTOR>` | Makes the broker try this CSS selector first for one step. Only a fill step or a click submit takes one. |
| `kharon teach clear-stale <DOMAIN>` | Clears the "stale" mark (below) once you have fixed the problem. |
| `kharon teach remove <DOMAIN>` | Removes the site's method. Fills there go back to the ordinary path. |

`import` refuses, and says why:

| Reason | Meaning |
|---|---|
| `invalid_method` | The file parses but is not a usable method (the wrong number of parts, a password step that is not a password field, a bad path). `kharon teach import` itself refuses a file with an unknown version or field before it connects, with exit code 2. It also refuses a method too large for the owner socket's 32 KiB request limit. |
| `off_domain` | The method's `site.domain` is not the registrable domain of its `site.origin`. |
| `main_world` | The recording was made with the listener in the page's own script world, where the page's scripts can see and fake what it reports. Pass `--accept-main-world` if you have read the method and trust it. |
| `rung_above_ceiling` | The method asks for `milliseconds` but its recording only showed `agent_continues`. |
| `method_exists` | The site already has a method. Pass `--replace`. |

A hand-written method has no recording, so the `main_world` and `rung_above_ceiling` checks do not apply to it. `--replace` also clears the site's overrides and its stale mark.

The registry is the file `teach/registry.json` under the daemon's data directory. It is private to the owner (mode `0600` in a `0700` directory). The daemon will not start on a registry file it cannot trust: one with the wrong mode, a version it does not know, or an entry filed under the wrong domain. Each import, override, clear-stale and remove writes one line to the audit log before it changes anything: the domain, the method's recording digest (or `hand_written`), and for an override the step number, never the selector. If the line cannot be written, nothing changes.

## What a fill does on a taught site

A method governs a fill that asks for a user name or a password, on a page whose site has an entry in the registry. The site is found from the page's own address as the browser reports it, never from what the agent says. A fill for a one-time code only never looks at the registry.

On such a page the agent still names the item and which kinds it wants. The method decides the rest:

- **Where the fields are.** The agent's selectors are ignored, and so are the broker's usual guesses. If the agent sent a selector, the reply says `method_selectors`.
- **Before anything is typed.** In one step in the page, kharon checks the page's address and every field of this part of the login. The page must have the login's origin and the part's path. For each field, kharon uses the first of the method's selectors (yours first) that matches exactly one element. That element must be visible and have the tag, `type`, `id`, `name` and `autocomplete` the method recorded, and a password field must be a password field now. If any check fails, nothing is typed. The elements are checked again just before each write.
- **What is typed.** Only the fields this part of the login has. A kind the agent asked for that the part has no field for is not sent. A kind the part needs that the agent did not ask for stops the fill before any value is sent.
- **Submit.** At `milliseconds`, and for each part of a two-step login, the fill always submits, with the method's own submit. When the part has a password step it also always runs the clean-up after the submit (the post-submit scrub, see [`post-fill-exposure.md`](post-fill-exposure.md)). The agent's `submit` and the deploy's scrub setting do not change this, so an agent that sends `submit: false` does not leave the password sitting in the page. A one-part `agent_continues` method, which only a person can write by hand, keeps the agent's `submit`.
- **The result.** After a submit, kharon looks after the scrub's delay (once more after the delay if the page had already moved on without showing the expected path) and records on the entry whether the login worked (`succeeded`), plainly did not (`failed`), or cannot be told (`unconfirmed`). The fill's reply is still `filled`.

A two-step login is two fills. On the user name page the agent asks for `username`, and on the password page it asks for `password`. The broker picks the part whose path matches the page.

A fill the method stopped has status `field_not_found` and one of these details:

| Detail | What happened | What the agent should do |
|---|---|---|
| `method_wrong_page` | The page is not one the method has a part for: another origin on the site, another path, a consent page, a redirect that has not finished. Nothing was typed, nothing is recorded and the owner hears nothing. | Go to the login page, wait for it to load, and ask again. |
| `method_not_ready` | The page matches, but a field is disabled (a page that enables its form late). Nothing was typed. The result is recorded; the entry is not marked. | Wait a moment and ask again. |
| `method_drift` | The page has the right path but a field has gone, is ambiguous, or has changed type, `id` or `name`. Nothing was typed. The entry is marked stale, with the step number, and the owner gets one notification. | Stop and tell the person that the login for this site changed. Do not retry: fills there are refused until the owner acts. |
| `method_stale` | The entry is already stale. Nothing was sent to the browser. | Stop and tell the person. |
| `method_field_not_requested` | The part of the login on this page needs a user name or a password that the request did not ask for. Nothing was typed. | Ask again with every kind the page needs. |

A `method_stale` or `method_field_not_requested` reply always sends no value to the browser and gives the grant use back. So does `method_wrong_page` when the broker sees the wrong page before the call. If the page changed between the broker's read and the check in the page, the in-page check refuses it: nothing is typed and nothing is recorded, but the values went with the call and the grant use is spent. None of the three writes to the registry or notifies the owner, and none counts toward the origin-mismatch limit.

A stale entry refuses fills on its site until the owner re-imports a method (`kharon teach import --replace`) or runs `kharon teach clear-stale <DOMAIN>`. Setting an override does not clear the mark. Falling back to the ordinary fill would type into whatever a changed page now has in that place, so kharon refuses and tells the owner instead. The notification reads: "The login page of DOMAIN no longer matches its method (step N). Fills there are refused until you re-import it or run: kharon teach clear-stale DOMAIN". It names the domain and a step number and nothing else.

The approval prompt (the ntfy message, `kharon grants` and the web page) shows the method's rung when the page's site has a method. A fill's reply carries a `rung` field (`milliseconds` or `agent_continues`) whenever a method governed it, and the fill's audit entry carries the same. When a fill drifts, the audit entry also carries the step number.

## Writing a method by hand

Some logins cannot be converted: a bank that encrypts the password in the page with a key the site supplies, or a login you cannot record. A person can write the method file instead. It is one JSON file. The program that reads it refuses a field it does not know, so a typing mistake is caught at once.

| Field | What it holds |
|---|---|
| `format_version` | `1` |
| `site` | `domain`: the registrable domain (`example.com`). `origin`: the login page's scheme and host, with the port if it has one (`https://login.example.com`). `path`: the login page's path, where the first part of the login starts. No query and no fragment. |
| `shape` | `{"kind": "form_post"}`, `{"kind": "script_post"}`, `{"kind": "two_step", "password_leg": "form_post"}` (the password part's own shape: `form_post`, `script_post` or `transformed`), or `{"kind": "transformed", "digest": null}` for a page that changes the password in a way kharon cannot name. `unrecognized` is refused. |
| `rung` | `"agent_continues"` unless you have checked that the site submits in one step from the fields you list. The broker takes your word for it. |
| `legs` | A list with one part for a one-page login and two for `two_step`. Each part is `{"steps": [...]}`. |
| `success` | `{"kind": "path_changed_to", "path": "/account"}`, `{"kind": "password_field_gone"}` or `{"kind": "none"}`. |
| `provenance` | `{"source": "hand_written", "author": "your name"}`. |

A part is its steps in order. It must begin with a `navigate`, hold at least one `fill`, and end with exactly one `submit`. The last part must have a password `fill`.

- `{"kind": "navigate", "path": "/signin"}`: the path the part starts on. For the first part it must equal `site.path`. The agent navigates; kharon only compares.
- `{"kind": "fill", "role": "username" | "password", "selectors": [...], "expect": {...}}`: `selectors` is a list of CSS selectors, most stable first, at least one, each at most 1,024 bytes. `expect` is `tag`, `input_type`, `id`, `name` and `autocomplete`. `tag` is required and lowercase (`input`, `button`). `input_type`, `id`, `name` and `autocomplete` may each be `null` or left out, and each that is set must match the live element. A password step must have `"input_type": "password"`.
- `{"kind": "submit", "via": {"kind": "form"}}` calls `requestSubmit()` on the form of the last field. `{"kind": "submit", "via": {"kind": "enter"}}` presses Enter on the last field. `{"kind": "submit", "via": {"kind": "click", "selectors": [...], "expect": {...}}}` clicks one element, found and checked like a field.

A selector cannot reach into a shadow root, so a method that needs one ends in `method_drift` on its first fill. Do not write one for such a login.

A complete example: one page, a click submit, and a password the page changes in a way kharon cannot name.

```json
{
  "format_version": 1,
  "site": {
    "domain": "example.com",
    "origin": "https://login.example.com",
    "path": "/signin"
  },
  "shape": { "kind": "transformed", "digest": null },
  "rung": "agent_continues",
  "legs": [
    {
      "steps": [
        { "kind": "navigate", "path": "/signin" },
        {
          "kind": "fill",
          "role": "username",
          "selectors": ["#user", "input[name=login]"],
          "expect": {
            "tag": "input",
            "input_type": "text",
            "id": "user",
            "name": "login",
            "autocomplete": "username"
          }
        },
        {
          "kind": "fill",
          "role": "password",
          "selectors": ["#pass", "input[name=secret]"],
          "expect": {
            "tag": "input",
            "input_type": "password",
            "id": "pass",
            "name": "secret",
            "autocomplete": null
          }
        },
        {
          "kind": "submit",
          "via": {
            "kind": "click",
            "selectors": ["button#go", "button[type=submit]"],
            "expect": {
              "tag": "button",
              "input_type": "submit",
              "id": "go",
              "name": null,
              "autocomplete": null
            }
          }
        }
      ]
    }
  ],
  "success": { "kind": "path_changed_to", "path": "/account" },
  "provenance": { "source": "hand_written", "author": "A. Person" }
}
```

Check a file with `kharon-teach show <FILE>` before you import it. `show` refuses a file that does not parse or does not pass the checks above. `kharon teach list` marks a hand-written method.

## What is not built yet

- Putting the password into the page without it ever sitting there, by swapping it into the request as it leaves the browser (rung 1 of #361, tracked in #384). Today the strongest rung is `milliseconds`: the password is in the page for the milliseconds between the fill and the submit.
- Logins with a one-time code. A recording notes the `otp_step` flag. A method has no step for it.
- Sharing methods between brokers. A method lives in one broker's registry. Copy the file and import it on the other one.
- Converting a login that needs a person (`unrecognized`, or a `transformed` login with no named digest). These are written by hand.
- A login with a field in a shadow root. Neither a converted nor a hand-written method can reach one; the first fill ends in `method_drift`.

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
- A method cannot reach a field in a shadow root, and it cannot follow a login that sends the person through another site, a pop-up or a frame from another address. The recorder flags those and `kharon-teach method` refuses to convert them.
